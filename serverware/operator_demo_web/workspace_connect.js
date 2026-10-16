// Guided composition of the same independent resources and mutation gate.
// Only public IDs/drafts live here; the applications controller owns all tokens.
function operatorConnectResourceChoices(items, reserved = []) {
  const actionLabels = reserved.map(value => value.replace(/\s+/g, ' ').trim());
  const options = items.map(item => ({id: item.id, name: (item.name +
    (['google_oauth', 'x_oauth'].includes(item.auth_type) ? ' · ' + item.provider_account : '')).replace(/\s+/g, ' ').trim()}));
  let result = options.map(item => {
    const peers = options.filter(other => other.id !== item.id && other.name === item.name);
    if (!peers.length && !actionLabels.includes(item.name)) return item;
    let length = Math.min(8, item.id.length);
    while (length < item.id.length && peers.some(other => other.id.slice(0, length) === item.id.slice(0, length))) length++;
    return {id: item.id, name: item.name + ' · ' + item.id.slice(0, length)};
  });
  // A literal name may imitate a generated label. Prefix the exact ID only for
  // colliding entries; each pass converts another entry, bounded by list size.
  // Unique persisted UUIDs make these final prefixes distinct regardless of name.
  for (let pass = 0; pass < options.length; pass++) {
    const counts = new Map();
    for (const name of [...actionLabels, ...result.map(item => item.name)]) counts.set(name, (counts.get(name) || 0) + 1);
    if (result.every(item => counts.get(item.name) === 1)) break;
    result = result.map((item, index) => counts.get(item.name) > 1 ?
      {id: item.id, name: '[' + item.id + '] ' + options[index].name} : item);
  }
  return result;
}
function operatorCredentialCanSetUpAccess(item, catalog) {
  if (!catalog || item?.status !== 'active') return false;
  if (isAwsCredential(item)) return ecrAvailable(catalog, item);
  if (isCommonAppCredential(item)) return commonAppAvailable(catalog, item);
  if (isGithubCredential(item)) return githubAvailable(catalog, item);
  if (isNpmCredential(item)) return npmAvailable(catalog, item) || npmInstallAvailable(catalog, item) || npmPublishAvailable(catalog, item);
  if (isXCredential(item)) return xAvailable(catalog, item);
  if (isXOAuthCredential(item)) return xPostAvailable(catalog, item);
  if (isAlchemyCredential(item)) return alchemyAvailable(catalog, item);
  if (item.auth_type === 'google_oauth') return gmailAvailable(catalog, item);
  return !item.connection_type && ['bearer', 'header'].includes(item.auth_type);
}
function operatorSavedKeyIdentity(item) {
  // Never retain the receipt object: only the public identity required to match
  // this newly saved key to the later catalog read belongs in the checkpoint.
  return Object.fromEntries(['id', 'name', 'status', 'auth_type', 'header_name', 'connection_type',
    'provider_id', 'app_preset', 'created_at', 'active_rule_count', 'credential_generation', 'key_replaced_at',
    'legacy_upstream_origin'].map(key => [key, item[key] ?? null]));
}
function createConnectView(workspace, applications, proxy) {
  const steps = ['credential', 'application', 'access', 'review', 'setup'];
  const labels = ['Credential', 'Client', 'Permission', 'Review access', 'Client setup'];
  const actionLabels = {credential: 'Choose a saved credential', application: 'Create a new client', rule: 'Grant a new permission'};
  let step = 0; let selectedCredential = ''; let selectedApplication = ''; let selectedRule = '';
  let review = null; let checkpoint = null; let open = false;
  let connectionMethod = null; let savedChoice = ''; let beforeGoogle = null;
  let selectedCommonApp = '';
  let saveOnly = false; let savedCredential = '';
  let pendingCredentialFocus = '';
  let includeDiagnostics = false;
  element('connect-x-post-quota').value = 'none';
  const catalog = () => workspace.state.catalog;
  const newGithubApp = () => connectionMethod === 'github' && element('connect-github-type').value === 'github_app_v1';
  const githubCreationAvailable = () => newGithubApp() ? githubAppDestinationAvailable(catalog()) :
    element('connect-github-type').value === 'github_token_v1' && Boolean(projectGithubCapability(catalog()?.capabilities.github));
  const writable = () => Boolean(catalog() && !workspace.state.busy && !workspace.state.uncertain);
  const canAddCredential = () => writable() && !checkpoint && connectionMethod !== 'google' && workspace.ready('credentials');
  function credentialTemplateAvailable(template) {
    if (!template || !['key', 'github', 'npm', 'x', 'alchemy', 'common'].includes(template.method)) return false;
    if (template.method === 'common') return Boolean(commonAppPreset(catalog(), template.appPreset));
    if (template.method === 'github') return template.githubType === 'github_app_v1' ? githubAppDestinationAvailable(catalog()) :
      template.githubType === 'github_token_v1' && Boolean(catalog()?.capabilities.github);
    if (template.method === 'npm') return Boolean(catalog()?.capabilities.npm);
    if (template.method === 'x') return xDestinationAvailable(catalog());
    if (template.method === 'alchemy') return alchemyDestinationAvailable(catalog());
    return true;
  }
  function chooseCredentialTemplate(template) {
    if (!credentialTemplateAvailable(template)) return false;
    connectionMethod = template.method; selectedCommonApp = template.appPreset || '';
    if (template.method === 'github') element('connect-github-type').value = template.githubType;
    const names = {key: 'API key', github: template.githubType === 'github_app_v1' ? 'GitHub App' : 'GitHub token',
      npm: 'npm token', x: 'X lookup token', alchemy: 'Alchemy key', common: (commonAppPreset(catalog(), selectedCommonApp)?.label || 'App') + ' key'};
    element('connect-credential-name').value = names[template.method];
    if (template.method === 'x') element('connect-x-name').value = names.x;
    if (template.method === 'alchemy') element('connect-alchemy-name').value = names.alchemy;
    element('connect-credential-choice').value = '';
    return true;
  }
  function focusCredentialSecret() {
    pendingCredentialFocus = connectionMethod === 'x' ? 'connect-x-secret' : connectionMethod === 'alchemy' ? 'connect-alchemy-secret' :
      newGithubApp() ? 'connect-github-app-id' : 'connect-credential-secret';
    focusVisibleCredential();
  }
  function focusVisibleCredential() {
    if (!open || !pendingCredentialFocus || location.hash !== '#connect') return;
    const input = element(pendingCredentialFocus);
    if (input.matches(':disabled') || !input.getClientRects().length) return;
    // Hash navigation can finish after the first animation frame. Focus only
    // once the router has shown and rendered this editor, never a hidden form.
    input.focus();
    if (document.activeElement === input) pendingCredentialFocus = '';
  }
  const credential = () => catalog()?.credentials.find(item => item.id === selectedCredential && item.status === 'active' && (!isAwsCredential(item) || ecrAvailable(catalog(), item)));
  const commonPreset = () => catalog()?.capabilities?.common_apps ? commonAppPreset(catalog(), connectionMethod === 'common' ? selectedCommonApp : credential()?.app_preset) : null;
  const application = () => catalog()?.applications.find(item => item.id === selectedApplication && item.status === 'active');
  const validApp = item => item?.token_status === 'valid' && Number.isSafeInteger(item.token_expires_at_epoch_ms) && item.token_expires_at_epoch_ms > Date.now();
  const matchingRules = () => catalog()?.access_rules.filter(item => item.status === 'active' && item.application_id === selectedApplication && item.credential_id === selectedCredential) || [];
  const metadataGrantAvailable = () => npmNewRuleAvailable(catalog(), selectedApplication) &&
    !catalog()?.access_rules.some(item => item.status === 'active' && item.application_id === selectedApplication && isNpmPublishRule(item));
  const publishGrantAvailable = () => npmPublishNewRuleAvailable(catalog(), selectedApplication) &&
    !catalog()?.access_rules.some(item => item.status === 'active' && item.application_id === selectedApplication && isNpmInstallRule(item));
  const message = text => { element('connect-status').textContent = text; };
  renderOperatorCompatibility('connect-compatibility-content');
  const accountSummary = textNode('div'); accountSummary.id = 'connect-google-account-summary';
  accountSummary.hidden = true; element('connect-progress').after(accountSummary);
  function renderGoogleAccount() {
    const id = step === 0 ? element('connect-credential-choice').value : selectedCredential;
    const item = catalog()?.credentials.find(item => item.id === id);
    const expanded = accountSummary.firstElementChild?.dataset.resourceId === id && accountSummary.querySelector('details')?.open;
    accountSummary.hidden = connectionMethod === 'google' || step === 0 && connectionMethod !== 'saved' || item?.auth_type !== 'google_oauth';
    accountSummary.replaceChildren();
    if (accountSummary.hidden) return;
    const card = operatorGoogleAccountCard(item, catalog());
    card.querySelector('details').open = Boolean(expanded);
    accountSummary.append(card);
  }

  // A vanished choice remains visibly unavailable: never silently pick another
  // resource, permission or capability after refresh.
  function choices(id, items, initial) {
    const control = element(id); const previous = control.value;
    const value = previous || initial;
    const options = items.map(item => { const option = textNode('option', item.name); option.value = item.id; return option; });
    if (value && !items.some(item => item.id === value)) {
      const missing = textNode('option', 'Previous choice unavailable — choose again'); missing.value = value; missing.disabled = true; options.push(missing);
    }
    if (!options.length) { const empty = textNode('option', 'No supported choice available'); empty.value = ''; options.push(empty); }
    control.replaceChildren(...options); control.value = value || options[0].value;
  }
  function fields(id, active) {
    element(id).hidden = !active;
    for (const control of element(id).querySelectorAll('input,select,textarea')) control.disabled = !active;
  }
  function goto(next) { step = next; render(); if (open) element('connect-progress').scrollIntoView({block: 'nearest'}); }
  function activePair() { return credential() && validApp(application()); }
  function supported(rule) { return operatorRuleSupported(rule, catalog()); }
  function gmailAgeInput() {
    const mode = element('connect-gmail-age-policy').value;
    return gmailAgePolicy(mode === 'unrestricted' ? {mode} :
      {mode, max_age_days: Number(element('connect-gmail-age-days').value)});
  }
  function gmailAgeProblem() {
    try {
      const policy = gmailAgeInput();
      return policy.mode !== 'unrestricted' && !gmailRecentAvailable(catalog()) ?
        'The last-N-days policy is no longer advertised. Refresh or explicitly choose all mail; no permission is changed automatically.' : '';
    } catch (error) { return operatorMessage(error); }
  }
  function gmailSdkRule() {
    return {...gmailRuleFields(gmailAgeInput()), name: 'Read Gmail', application_id: selectedApplication, credential_id: selectedCredential,
      credential_input: 'replace_exact', placeholder: 'Bearer serverware-gmail-placeholder-v1'};
  }
  function gmailSdkProblem() {
    const ageProblem = gmailAgeProblem(); if (ageProblem) return ageProblem;
    if (!gmailAvailable(catalog(), credential()) || !catalog()?.allowed_upstreams.includes(operatorGmail.origin) ||
        !availableCredentialInputModes(catalog()).includes('replace_exact'))
      return 'The exact Read Gmail permission, approved Gmail destination and dummy-header replacement must all be advertised. No fallback permission is selected.';
    if (!projectApplicationProxyAuthenticationCapability(catalog()?.capabilities?.application_proxy_authentication))
      return 'Standard username/password proxy login is not advertised. The official SDK choice is unavailable; no login mode or permission is changed.';
    if (applicationProxyAuthentication(application()) !== 'basic_and_bearer_v1')
      return 'The official Gmail SDK needs standard username/password proxy login. In Clients, explicitly enable it for this app, then refresh here. No token or login mode is changed automatically.';
    if (!supported(gmailSdkRule())) return 'This account, application or Gmail permission is unavailable. Refresh and review again; no fallback grant is sent.';
    return '';
  }
  function confirmCheckpoint() {
    if (!checkpoint || !catalog() || workspace.state.busy || workspace.state.uncertain || catalog().revision < checkpoint.revision) return;
    if (checkpoint.ecrPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.ecrPolicyHash) {
      checkpoint.message = 'The ECR receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.xPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.xPolicyHash) {
      checkpoint.message = 'The saved X receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.alchemyPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.alchemyPolicyHash) {
      checkpoint.message = 'The saved Alchemy receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.githubAppPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.githubAppPolicyHash) {
      checkpoint.message = 'The saved GitHub App receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.savedKey && catalog().revision === checkpoint.revision &&
        (catalog().policy.policy_hash !== checkpoint.savedKeyPolicy.policy_hash || catalog().policy.sequence !== checkpoint.savedKeyPolicy.sequence)) {
      checkpoint.message = 'The credential receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    const item = catalog()[checkpoint.collection].find(item => item.id === checkpoint.id && item.status === 'active');
    if (!item) { message('The exact saved resource cannot be confirmed. Review saved state; no repeat request was sent.'); return; }
    if (checkpoint.collection === 'credentials') {
      if (checkpoint.savedKey && !operatorExact(operatorSavedKeyIdentity(item), checkpoint.savedKey)) {
        checkpoint.message = 'The saved credential does not match its creation receipt. Inspect saved state; do not submit again.'; return;
      }
      if (isAwsCredential(item) && !ecrAvailable(catalog(), item)) { checkpoint.message = 'ECR publication is not available for this AWS credential.'; return; }
      if (checkpoint.github && item.connection_type !== 'github_token_v1') {
        message('The saved GitHub connection cannot be confirmed. Refresh saved state; do not submit again.'); return;
      }
      if (checkpoint.githubApp && !githubAppCredentialReceiptMatches(item, checkpoint.githubApp)) {
        checkpoint.message = 'The saved GitHub App binding does not match its creation receipt. Inspect saved state; do not submit again.'; return;
      }
      if (checkpoint.npm && !isNpmCredential(item)) {
        message('The saved npm connection cannot be confirmed. Refresh saved state; do not submit again.'); return;
      }
      if (checkpoint.x) {
        if (!xCredentialReceiptMatches(item, checkpoint.x)) {
          checkpoint.message = 'The saved X connection does not match its creation receipt. Inspect saved state; do not submit again.'; return;
        }
      }
      if (checkpoint.alchemy && !alchemyCredentialReceiptMatches(item, checkpoint.alchemy)) {
        checkpoint.message = 'The saved Alchemy connection does not match its creation receipt. Inspect saved state; do not submit again.'; return;
      }
      selectedCredential = item.id; selectedApplication = ''; selectedRule = ''; review = null;
      connectionMethod = 'saved'; savedChoice = item.id;
      element('connect-credential-choice').value = ''; renderInputs();
      element('connect-credential-choice').value = item.id;
      if (saveOnly) { savedCredential = item.id; step = 0; }
      else step = 1;
    }
    if (checkpoint.collection === 'applications') {
      if (!validApp(item)) { message('The saved application token is not currently valid. Use Clients for explicit rotation.'); return; }
      selectedApplication = item.id; selectedRule = ''; review = null; element('connect-application-choice').value = item.id; step = 2;
      renderInputs(); // The new app is now an exact confirmed pair; initialize its permission choice before showing access.
    }
    if (checkpoint.collection === 'access_rules') {
      if (isCommonAppRule(review?.rule) && (!commonAppRuleValid(item, credential(), catalog()) ||
          !operatorExact(commonAppRulePayload(item), commonAppRulePayload(review.rule)) ||
          catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.commonPolicyHash)) {
        checkpoint.message = 'The saved app permission differs from the reviewed scopes. Inspect saved state; do not submit again.'; return;
      }
      if ((item.approval_mode ?? 'automatic') !== (review?.rule.approval_mode ?? 'automatic')) {
        message('The saved human-approval requirement differs from the reviewed permission. Inspect saved state; no repeat request was sent.'); return;
      }
      if (item.application_id !== selectedApplication || item.credential_id !== selectedCredential) { message('Saved rule references did not match this setup. Review saved state.'); return; }
      if (isGmailRule(review?.rule) && (!gmailRuleValid(item, credential()) || item.query_mode !== review.rule.query_mode ||
          !operatorExact(gmailRulePayload(item), gmailRulePayload(review.rule)))) {
        message('The saved permission does not match the reviewed Read Gmail configuration. Review saved state; no repeat request was sent.'); return;
      }
      if (isGithubRule(review?.rule) && (!githubRuleValid(item, credential()) ||
          !operatorExact(githubRulePayload(item), githubRulePayload(review.rule)))) {
        message('The saved GitHub permission does not match the reviewed repository and operation. Refresh; no repeat request was sent.'); return;
      }
      if (isNpmInstallRule(review?.rule) && (!npmInstallRuleValid(item, credential()) ||
          !operatorExact(npmInstallRulePayload(item), npmInstallRulePayload(review.rule)))) {
        message('The saved installation permission does not match the reviewed dependency allowlist. Refresh; no repeat request was sent.'); return;
      }
      if (isNpmRule(review?.rule) && (!npmRuleValid(item, credential()) ||
          !operatorExact(npmRulePayload(item), npmRulePayload(review.rule)))) {
        message('The saved npm permission does not match the reviewed packages. Refresh; no repeat request was sent.'); return;
      }
      if (isNpmPublishRule(review?.rule) && (!npmPublishRuleValid(item, credential()) ||
          !operatorExact(npmPublishRulePayload(item), npmPublishRulePayload(review.rule)))) {
        message('The saved publishing permission does not match the reviewed package, tag and UTC hours. Refresh; no repeat request was sent.'); return;
      }
      if (isXRule(review?.rule) && (!xRuleValid(item, credential()) ||
          !operatorExact(xRulePayload(item), xRulePayload(review.rule)))) {
        checkpoint.message = 'The saved X permission does not match the reviewed username and connection. Inspect saved state; no repeat request was sent.'; return;
      }
      if (isXPostRule(review?.rule) && (!xPostRuleValid(item, credential()) ||
          !operatorExact(xPostRulePayload(item), xPostRulePayload(review.rule)))) {
        checkpoint.message = 'The saved X posting permission does not match the reviewed account. Inspect saved state; no repeat request was sent.'; return;
      }
      if (isAlchemyRule(review?.rule) && (!alchemyRuleValid(item, credential()) ||
          !operatorExact(alchemyRulePayload(item), alchemyRulePayload(review.rule)))) {
        checkpoint.message = 'The saved Alchemy permission does not match the reviewed chain and connection. Inspect saved state; no repeat request was sent.'; return;
      }
      if (isEcrRule(review?.rule) && (!ecrRuleValid(item, credential()) || !operatorExact(ecrRulePayload(item), ecrRulePayload(review.rule)))) {
        checkpoint.message = 'The saved ECR permission differs from the reviewed account, region, repository or tag. Inspect saved state; do not submit again.'; return;
      }
      selectedRule = item.id; step = 4;
    }
    checkpoint = null; message(saveOnly && savedCredential ?
      'Credential saved and confirmed in the refreshed inventory. No client or permission was created.' :
      'Saved resource confirmed in the refreshed catalog.');
  }
  function receipt(result, collection, key, providerName, providerKind) {
    if (!result[key] || typeof result[key].id !== 'string' || !Number.isSafeInteger(result.revision))
      throw operatorError('The saved resource receipt was incomplete. Review saved state; do not repeat automatically.');
    if (collection === 'access_rules' && (result[key].approval_mode ?? 'automatic') !== (review?.rule.approval_mode ?? 'automatic'))
      throw operatorError('The saved human-approval requirement differs from the reviewed permission. Inspect saved state; no repeat request was sent.');
    const commonMutation = collection === 'access_rules' && isCommonAppRule(review?.rule);
    const ecrMutation = collection === 'access_rules' && isEcrRule(review?.rule);
    if (ecrMutation && (result.revision !== catalog().revision + 1 || result[key].status !== 'active' ||
        result.policy?.sequence !== catalog().policy.sequence + 1 || !/^sha256:[a-f0-9]{64}$/.test(result.policy?.policy_hash || '') ||
        result.policy.policy_hash === catalog().policy.policy_hash || !ecrRuleValid(result[key], credential()) ||
        !operatorExact(ecrRulePayload(result[key]), ecrRulePayload(review.rule))))
      throw operatorError('The saved ECR receipt did not match the exact reviewed scope and policy. Inspect saved state; do not repeat it.');
    if (commonMutation && (result.revision !== catalog().revision + 1 || result[key].status !== 'active' ||
        !/^sha256:[a-f0-9]{64}$/.test(result.policy?.policy_hash || '') ||
        !commonAppRuleValid(result[key], credential(), catalog()) ||
        !operatorExact(commonAppRulePayload(result[key]), commonAppRulePayload(review.rule))))
      throw operatorError('The saved app permission receipt did not match the reviewed operation. Inspect saved state; do not repeat it.');
    const xMutation = providerName !== undefined && providerKind === 'x' || collection === 'access_rules' && (isXRule(review?.rule) || isXPostRule(review?.rule));
    const alchemyMutation = providerName !== undefined && providerKind === 'alchemy' || collection === 'access_rules' && isAlchemyRule(review?.rule);
    const githubAppMutation = providerKind === 'github_app' || collection === 'access_rules' && isGithubAppCredential(credential());
    if ((xMutation || alchemyMutation || githubAppMutation) && (result.revision < 1 || result.revision <= catalog().revision || result[key].status !== 'active' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(result[key].id) ||
        !/^sha256:[a-f0-9]{64}$/.test(result.policy?.policy_hash || '')))
      throw operatorError('The saved ' + (githubAppMutation ? 'GitHub App' : alchemyMutation ? 'Alchemy' : 'X') + ' receipt was incomplete. Inspect saved state; do not repeat automatically.');
    if (githubAppMutation && collection === 'access_rules' && (!githubRuleValid(result[key], credential()) ||
        !operatorExact(githubRulePayload(result[key]), githubRulePayload(review.rule))))
      throw operatorError('The GitHub App permission receipt did not match the reviewed repository and permission. Inspect saved state; do not repeat automatically.');
    if (collection === 'access_rules' && isXRule(review?.rule) && (!xRuleValid(result[key], credential()) ||
        !operatorExact(xRulePayload(result[key]), xRulePayload(review.rule))))
      throw operatorError('The X permission receipt did not match the reviewed username. Inspect saved state; do not repeat automatically.');
    if (collection === 'access_rules' && isXPostRule(review?.rule) && (!xPostRuleValid(result[key], credential()) ||
        !operatorExact(xPostRulePayload(result[key]), xPostRulePayload(review.rule))))
      throw operatorError('The X posting receipt did not match the reviewed account. Inspect saved state; do not repeat automatically.');
    if (collection === 'access_rules' && isAlchemyRule(review?.rule) && (!alchemyRuleValid(result[key], credential()) ||
        !operatorExact(alchemyRulePayload(result[key]), alchemyRulePayload(review.rule))))
      throw operatorError('The Alchemy permission receipt did not match the reviewed chain. Inspect saved state; do not repeat automatically.');
    checkpoint = {collection, id: result[key].id, revision: result.revision,
      ...(ecrMutation ? {ecrPolicyHash: result.policy.policy_hash} : {}),
      ...(commonMutation ? {commonPolicyHash: result.policy.policy_hash} : {}),
      ...(xMutation ? {xPolicyHash: result.policy.policy_hash} : {}),
      ...(alchemyMutation ? {alchemyPolicyHash: result.policy.policy_hash} : {}),
      ...(githubAppMutation ? {githubAppPolicyHash: result.policy.policy_hash} : {}),
      ...(collection === 'credentials' && githubAppMutation ? {githubApp: githubAppCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && xMutation ? {x: xCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && alchemyMutation ? {alchemy: alchemyCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && connectionMethod === 'github' && !githubAppMutation ? {github: true} : {}),
      ...(collection === 'credentials' && connectionMethod === 'npm' ? {npm: true} : {})};
  }
  function keyCreationReceipt(result, submitted) {
    const item = result?.credential;
    if (!item || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.id) ||
        submitted.ids.includes(item.id) || result.revision !== submitted.revision + 1 ||
        result.policy?.policy_hash !== submitted.policy.policy_hash || result.policy?.sequence !== submitted.policy.sequence ||
        Object.hasOwn(result, 'client_token') || item.status !== 'active' || item.active_rule_count !== 0 ||
        Object.entries(submitted.fields).some(([key, value]) => (item[key] ?? null) !== value) ||
        typeof item.created_at !== 'string' || !Number.isFinite(Date.parse(item.created_at)) ||
        item.legacy_upstream_origin != null || item.revoked_at != null || Object.hasOwn(item, 'key_replaced_at') ||
        Object.hasOwn(item, 'credential_generation') && item.credential_generation !== 1)
      throw operatorError('The credential creation receipt did not match the submitted provider, name and authentication settings. Inspect saved state; do not submit again.');
    receipt(result, 'credentials', 'credential');
    checkpoint.savedKey = operatorSavedKeyIdentity(item);
    checkpoint.savedKeyPolicy = {...submitted.policy};
  }
  function renderInputs() {
    const value = catalog(); if (!value) return;
    const diagnostics = operatorDiagnosticResources(value);
    if (['key', 'github', 'npm', 'x', 'alchemy', 'common'].includes(connectionMethod)) choices('connect-credential-choice', [{id: 'new', name: 'New provider key'}], 'new');
    if (connectionMethod === 'saved') choices('connect-credential-choice', [{id: '', name: actionLabels.credential},
      ...operatorConnectResourceChoices(value.credentials.filter(item => item.status === 'active' && (!isAwsCredential(item) || ecrAvailable(value, item)) &&
        (includeDiagnostics || item.id === selectedCredential || item.id === savedChoice || !diagnostics.credentials.has(item.id))), [actionLabels.credential])], savedChoice);
    choices('connect-application-choice', [...operatorConnectResourceChoices(value.applications.filter(item => item.status === 'active' &&
      (includeDiagnostics || item.id === selectedApplication || !diagnostics.applications.has(item.id))), [actionLabels.application]), {id: 'new', name: actionLabels.application}], 'new');
    choices('connect-rule-choice', [{id: 'new', name: actionLabels.rule}, ...operatorConnectResourceChoices(matchingRules(), [actionLabels.rule])], 'new');
    choices('connect-origin', [{id: '', name: 'Choose an approved destination'},
      ...value.allowed_upstreams.map(origin => ({id: origin,
        name: origin === 'https://demo-upstream:8443' ? 'Local connection check (diagnostic)' : origin}))], '');
    choices('connect-credential-input', availableCredentialInputModes(value).map(id => ({id, name: operatorCredentialInputModes[id]})), 'insert');
    const responseChoices = responseFormChoices(value, element('connect-response-mode').value);
    choices('connect-response-mode', responseChoices, responseChoices[0]?.id);
    if (activePair()) {
      const bundle = gmailAvailable(value, credential());
      const github = isGithubCredential(credential());
      const npm = isNpmCredential(credential());
      const x = isXCredential(credential());
      const xPost = isXOAuthCredential(credential());
      const alchemy = isAlchemyCredential(credential());
      const common = isCommonAppCredential(credential());
      const commonChoices = common ? commonAppCreationOperations(commonPreset()).map(item => ({id: item.id, name: item.label})) : [];
      const npmChoices = npm ? [...(npmAvailable(value, credential()) ? [{id: operatorNpm.bundle, name: 'Read package metadata'}] : []),
        ...(npmInstallAvailable(value, credential()) ? [{id: operatorNpmInstall.bundle, name: 'Install packages and run npm audit'}] : []),
        ...(value.capabilities.npm_publish && npmPublishAvailable(value, credential()) ? [{id: 'npm_publish_v1', name: 'Publish package'}] : [])] : [];
      choices('connect-operation', isAwsCredential(credential()) ? [{id: operatorEcr.bundle, name: 'Publish a reviewed image to ECR'}] : common ? commonChoices : xPost ? xPostAvailable(value, credential()) ? [{id: operatorXPost.bundle, name: 'Publish text as this X account'}] : [] : alchemy ? alchemyAvailable(value, credential()) ? [{id: operatorAlchemy.bundle, name: 'Read chain status'}] : [] : x ? xAvailable(value, credential()) ? [{id: operatorX.bundle, name: 'Look up one X username'}] : [] : npm ? npmChoices : github ? githubAvailable(value, credential()) ?
        githubPermissionBundles(credential()).map(id => ({id, name: githubPermissionName(id)})) : [] :
        [...(bundle ? [{id: operatorGmail.bundle, name: 'Read Gmail'}] : []),
          {id: 'exact', name: 'Advanced: one exact endpoint'}], isAwsCredential(credential()) ? operatorEcr.bundle : common ? commonChoices[0]?.id : xPost ? operatorXPost.bundle : alchemy ? operatorAlchemy.bundle : x ? operatorX.bundle : npm ? npmChoices[0]?.id : github ? operatorGithub.read : bundle ? operatorGmail.bundle : 'exact');
      if (alchemy) {
        const select = element('connect-alchemy-chain'); const previous = select.value;
        const empty = textNode('option', 'Choose an approved chain'); empty.value = '';
        const options = operatorAlchemy.chains.map(chain => {
          const allowed = alchemyDestinationAvailable(value, chain);
          const option = textNode('option', (chain === 'eth-mainnet' ? 'Ethereum mainnet' : 'Ethereum Sepolia') + (allowed ? '' : ' · destination not approved'));
          option.value = chain; option.disabled = !allowed; return option;
        });
        select.replaceChildren(empty, ...options); select.value = previous;
      }
    }
  }
  function renderForms() {
    const newCredential = ['key', 'github', 'npm', 'x', 'alchemy', 'common'].includes(connectionMethod);
    const newApp = element('connect-application-choice').value === 'new';
    const newRule = element('connect-rule-choice').value === 'new';
    const gmail = newRule && element('connect-operation').value === operatorGmail.bundle;
    const gmailSdk = gmail && element('connect-gmail-client').value === 'sdk';
    const github = newRule && (isGithubCredential(credential()) || isGithubRule({operation_bundle: element('connect-operation').value}));
    const npm = newRule && (isNpmCredential(credential()) || isNpmRule({operation_bundle: element('connect-operation').value}));
    const npmPublish = npm && isNpmPublishRule({operation_bundle: element('connect-operation').value});
    const npmInstall = npm && isNpmInstallRule({operation_bundle: element('connect-operation').value});
    const x = newRule && (isXCredential(credential()) || isXRule({operation_bundle: element('connect-operation').value}));
    const xPost = newRule && isXOAuthCredential(credential());
    const alchemy = newRule && (isAlchemyCredential(credential()) || isAlchemyRule({operation_bundle: element('connect-operation').value}));
    const common = newRule && isCommonAppCredential(credential());
    const commonOperation = common ? commonAppCreationOperations(commonPreset()).find(item => item.id === element('connect-operation').value) : null;
    const gmailAgeProblemText = gmail ? gmailAgeProblem() : '';
    const gmailAge = gmail && !gmailAgeProblemText ? gmailAgeInput() : null;
    const ecr = newRule && isAwsCredential(credential());
    const providerPreset = github || npm || x || xPost || alchemy || common || ecr;
    fields('connect-saved-choice', connectionMethod === 'saved'); fields('connect-credential-new', newCredential && !['x', 'alchemy'].includes(connectionMethod));
    fields('connect-x-new', connectionMethod === 'x');
    fields('connect-alchemy-new', connectionMethod === 'alchemy');
    fields('connect-application-new', newApp); fields('connect-rule-new', newRule);
    fields('connect-credential-auth-group', connectionMethod === 'key');
    element('connect-credential-auth-details').hidden = connectionMethod !== 'key';
    fields('connect-github-type-group', connectionMethod === 'github' && !saveOnly);
    fields('connect-provider-secret-group', newCredential && !['x', 'alchemy'].includes(connectionMethod) && !newGithubApp());
    fields('connect-github-app-fields', newGithubApp());
    for (const option of element('connect-github-type').options) option.disabled = option.value === 'github_app_v1' ?
      !catalog()?.capabilities.github_app : !catalog()?.capabilities.github;
    element('connect-github-token-note').hidden = connectionMethod !== 'github' || newGithubApp();
    element('connect-npm-token-note').hidden = connectionMethod !== 'npm';
    element('connect-common-key-note').hidden = connectionMethod !== 'common';
    element('connect-common-key-note').textContent = connectionMethod === 'common' ? (commonPreset()?.secret_hint || '') +
      ' Saved encrypted; not tested or renewed automatically. No permissions are granted by saving. ' +
      (commonPreset()?.destination_allowed ? '' : 'Before granting access, review Proxy setup → Proxy destinations and approve ' +
        [...new Set((commonPreset()?.operations || []).map(item => item.origin))].join(', ') + '. A controlled restart applies destination changes.') : '';
    element('connect-credential-secret-label').textContent = connectionMethod === 'common' ? commonPreset()?.secret_label || 'Provider key' : 'Provider key or token';
    element('connect-npm-token-note').textContent = catalog()?.capabilities.npm_publish ?
      'Use a least-privilege npm token for the intended packages and operations. Publishing needs provider publishing rights without an interactive 2FA flow. The token stays in Serverware, never in the client recipe; it is not renewed or tested here.' :
      'Use a least-privilege npm token for reading the intended packages at registry.npmjs.org. It is saved only in Serverware, never put in the client recipe. Serverware does not renew or test this token.';
    if (connectionMethod === 'github') {
      element('connect-credential-secret').setAttribute('pattern', '[A-Za-z0-9_]{1,8192}');
      element('connect-credential-secret').title = 'Use a GitHub token, not an App JWT or private key.';
    } else {
      element('connect-credential-secret').removeAttribute('pattern');
      element('connect-credential-secret').removeAttribute('title');
    }
    const custom = connectionMethod === 'key' && element('connect-credential-auth-type').value === 'header';
    fields('connect-credential-header-group', custom); element('connect-credential-header-name').required = custom;
    const replacing = newRule && element('connect-credential-input').value === 'replace_exact';
    fields('connect-placeholder-group', replacing); element('connect-placeholder').required = replacing;
    try { element('connect-header-target').textContent = credentialHeaderTarget(credential()); }
    catch (_) { element('connect-header-target').textContent = 'Unsupported credential header'; }
    element('connect-placeholder').placeholder = element('connect-header-target').textContent === 'Authorization' ? 'Bearer SERVERWARE_DUMMY' : 'SERVERWARE_DUMMY';
    element('connect-input-help').textContent = !availableCredentialInputModes(catalog()).includes(element('connect-credential-input').value) ?
      'Choose an advertised credential-input mode. Unavailable choices cannot grant access.' : replacing ? 'Replacement applies only to this exact rule, not every use of the saved credential.' :
      'Automatic insertion: your client sends no provider credential header; Serverware supplies it after authorization.';
    const projected = newRule && element('connect-response-mode').value === 'projected_json';
    fields('connect-response-fields-group', projected); element('connect-response-fields').required = projected;
    renderOperatorRequestBodyForm('connect', catalog(), credential(), 'connect-body-warning', newRule);
    element('connect-response-limits').textContent = operatorResponseLimits(element('connect-response-mode').value);
    const content = review && step >= 3 ? review.rule : {response_mode: element('connect-response-mode').value};
    if (!(review && step >= 3) && element('connect-request-body-mode').value === 'preserve_json_v1') content.request_body_mode = 'preserve_json_v1';
    renderOperatorCompatibility('connect-compatibility-content', providerPreset && !(review && step >= 3) ?
      {operation_bundle: element('connect-operation').value} : gmail && !(review && step >= 3) ? {...gmailRuleFields(), age_policy: gmailAge} : content);
    renderBasicCompatibility('connect', catalog(), credential());
    // Apply these last: nested legacy field renderers must not re-enable hidden
    // required controls. Switching permissions never clears the exact-rule draft.
    element('connect-operation-group').hidden = x || xPost || alchemy || !newRule || credential()?.auth_type !== 'google_oauth' && !gmail && !providerPreset;
    fields('connect-exact-destination', newRule && !gmail && !providerPreset);
    fields('connect-ecr-permission', ecr);
    fields('connect-common-permission', common);
    if (common) renderCommonAppScopes(commonPreset(), commonOperation, true);
    else { element('connect-common-scopes').replaceChildren(); delete element('connect-common-scopes').dataset.signature; }
    element('connect-common-summary').textContent = commonOperation ? commonOperation.description + ' ' +
      (catalog().allowed_upstreams.includes(commonOperation.origin) ? 'Approved destination: ' : 'Destination not approved. Open Proxy setup → Approved destinations, then add ') + commonOperation.origin + '.' : '';
    element('connect-common-limits').textContent = commonOperation ?
      'Requests: at most 64 KiB. Success responses: at most 1 MiB. ' + (commonOperation.notes || []).join(' ') : '';
    element('connect-credential-input-group').hidden = !newRule || providerPreset || gmailSdk;
    if (!newRule || providerPreset || gmailSdk) for (const input of element('connect-credential-input-group').querySelectorAll('input,select,textarea')) input.disabled = true;
    fields('connect-gmail-client-group', gmail);
    const recentAge = element('connect-gmail-age-policy').value === 'recent_internal_date_v1';
    choices('connect-gmail-age-policy', [{id: 'unrestricted', name: 'All mail (no age restriction)'},
      ...(gmailRecentAvailable(catalog()) ? [{id: 'recent_internal_date_v1', name: 'Only mail from the last…'}] : [])], 'unrestricted');
    fields('connect-gmail-age-group', gmail && (gmailRecentAvailable(catalog()) || recentAge));
    fields('connect-gmail-age-days-group', gmail && recentAge);
    element('connect-gmail-age-policy').setCustomValidity(gmailAgeProblemText);
    element('connect-gmail-age-status').textContent = gmailAgeProblemText;
    element('connect-gmail-age-help').textContent = recentAge ?
      'Uses Gmail’s stored timestamp (internalDate), not the sender’s Date header. List requests need maxResults 1–32. Serverware checks message metadata; an old message or unverifiable age blocks the whole page. Search can narrow results but does not enforce this policy.' :
      'All mail keeps the existing unrestricted behavior. Choosing a time window affects only the new permission reviewed here, never an existing grant.';
    element('connect-gmail-sdk-summary').hidden = !gmailSdk;
    element('connect-gmail-sdk-status').textContent = gmailSdk ? gmailSdkProblem() ||
      'The fixed public dummy and standard proxy login are supported. Review the permission below; this page does not run the SDK or verify Google access.' :
      'Choose automatic insertion or your own exact public dummy below. These custom HTTP settings are retained when switching client choices; no saved permission is changed.';
    element('connect-gmail-sdk-app-link').hidden = !gmailSdk || applicationProxyAuthentication(application()) === 'basic_and_bearer_v1';
    fields('connect-github-repository', github);
    for (const [id, key] of [['connect-github-owner', 'owner'], ['connect-github-repo', 'name']]) {
      element(id).readOnly = isGithubAppCredential(credential());
      if (isGithubAppCredential(credential())) element(id).value = credential().github_app.repository[key];
    }
    element('connect-github-repository-note').textContent = isGithubAppCredential(credential()) ?
      'Repository fixed by this GitHub App connection. You may grant only its saved permission or less. No response-field setup is needed.' :
      'This is the exact named repository you authorize, not a discovered or verified account relationship. The saved token must already have the required GitHub permission. No response-field setup is needed.';
    fields('connect-x-username-group', x);
    fields('connect-x-post-group', xPost);
    const xPostQuotaProblem = xPost ? renderXPostQuotaForm(catalog(), credential(), true) : '';
    element('connect-x-post-summary').textContent = !xPost ? '' : !xPostAvailable(catalog(), credential()) ?
      'Posting is unavailable until this account, the approved destination and the current paired gate support the exact permission. No fallback grant is sent.' :
      'Publish text as ' + credential().provider_account + '. Text only; no media, replies, quotes or threads. Supply text only in your local client. ' +
      (xPostQuotaAvailable(catalog(), credential()) ? 'An optional shared daily posting-attempt restriction is available below.' :
        'The paired gate does not advertise daily limits. Do not grant unlimited access if you require a limit.');
    fields('connect-alchemy-chain-group', alchemy);
    element('connect-alchemy-summary').textContent = !alchemyAvailable(catalog(), credential(), element('connect-alchemy-chain').value) ?
      'Choose an approved mainnet or Sepolia chain. The exact preset and its separately approved origin are required. No destination is added and no fallback permission is sent.' :
      'Read eth_chainId and eth_blockNumber on this chain only. POST to keyless /v2 with params: []. No arbitrary RPC, batches, transactions or response-field setup. No provider request is sent here.';
    element('connect-x-summary').textContent = !xAvailable(catalog(), credential()) ?
      'X username lookup is unavailable: the exact preset and approved api.x.com destination are required. No fallback permission is sent.' :
      'Look up this one exact username. GET only, with no query or body. Fixed public dummy authentication; no response-field setup. No posting, search, user OAuth or provider verification.';
    fields('connect-npm-packages-group', npm && !npmPublish);
    element('connect-npm-packages-label').textContent = npmInstall ? 'Every package and dependency this app may install' : 'Package names this app may read';
    element('connect-npm-packages-help').textContent = npmInstall ?
      'Include all direct, transitive, optional and peer packages the job may fetch or audit. One exact name per line, 1–64 total. No automatic dependency discovery or grant. Review your manifests and lockfile; omit nothing required by the job.' :
      'One exact package name per line, 1–64 unique names. Scoped names use @scope/name. No wildcard, version suffix, URL or dependency-wide access.';
    fields('connect-npm-publish-group', npmPublish);
    fields('connect-npm-publish-window', npmPublish && element('connect-npm-publish-hours').value === 'window');
    element('connect-npm-publish-summary').textContent = !npmPublish ? '' : !npmPublishAvailable(catalog(), credential()) ?
      'Publishing is not advertised or registry.npmjs.org is not approved. No fallback permission is sent.' :
      !publishGrantAvailable() ?
        'This app already has an npm permission or overlapping registry GET/PUT rule. Reuse it or explicitly revoke the conflict before granting publishing.' :
        'Publish new versions of one exact package with the selected tag. Optional hours are daily UTC, not local time; no overnight interval or 24:00.';
    element('connect-npm-summary').textContent = npmInstall ? !npmInstallAvailable(catalog(), credential()) ?
      'Installation is unavailable until the live paired gate supports it and registry.npmjs.org is approved. No fallback grant is sent.' :
      !npmInstallNewRuleAvailable(catalog(), selectedApplication) ?
        'This application already has a registry permission. Explicitly revoke the conflict before granting installation; existing grants are never upgraded.' :
        'Metadata and tarball reads plus the fixed bulk npm audit request, for this exact package/dependency allowlist. No publishing. Use the reviewed example with lifecycle scripts disabled. This page has not verified a stock-client job.' : !npmAvailable(catalog(), credential()) ?
      'npm metadata lookup is unavailable: this deployment must advertise the preset and approve registry.npmjs.org. No fallback or grant is sent.' :
      !metadataGrantAvailable() ?
      'This application already has an npm permission or overlapping registry GET rule. Reuse its saved permission or review and explicitly revoke the conflicting rule before a new grant. Nothing is changed automatically.' :
      'Read package metadata for these exact packages only. Supports npm view and pacote.manifest; no install, publish, tarballs or npm audit. GET only, no request body or query parameters. No response-field setup.';
    element('connect-github-summary').textContent = !githubAvailable(catalog(), credential()) ?
      'GitHub permissions are unavailable: this deployment must advertise the preset and approve api.github.com. No fallback or grant is sent.' :
      githubPermissionName(element('connect-operation').value) + '. Named repository only; no edits, deletes or other APIs. The pinned client uses a fixed public dummy token; response content needs no setup.';
    element('connect-exact-content').hidden = !newRule || gmail || providerPreset;
    if (!newRule || gmail || providerPreset) for (const input of element('connect-exact-content').querySelectorAll('input,select,textarea')) input.disabled = true;
    element('connect-gmail-summary').hidden = !gmail;
    element('connect-gmail-summary').textContent = gmail && !gmailAvailable(catalog(), credential()) ?
      'Read Gmail is no longer advertised for this account. Refresh or explicitly choose another permission; no rule is changed automatically.' :
      'Read Gmail: list messages, follow pagination and read individual messages in this account. ' +
      (gmailAge?.mode === 'unrestricted' ? 'No age restriction or optional content filtering.' : gmailAgePolicySummary(gmailAge)) +
      ' No sending, changes, attachments, history or Calendar. GET only, no request body; bounded JSON responses only.';
    element('connect-credential-next').textContent = newGithubApp() ? 'Save and verify GitHub App' : newCredential ? saveOnly ? 'Save credential' : 'Save credential & continue' : 'Use saved credential';
    element('connect-credential-next').disabled = connectionMethod === 'common' && !commonPreset() || connectionMethod === 'github' && !githubCreationAvailable() ||
      !newCredential && !catalog()?.credentials.some(item => item.id === element('connect-credential-choice').value && item.status === 'active');
    element('connect-application-next').textContent = newApp ? 'Create client and show token' : 'Use this client';
    element('connect-application-proxy-default').textContent = newApplicationProxyAuthentication(catalog()).proxy_authentication ?
      'Proxy login: public application ID as username, this app’s token as password. Bearer also remains supported. Never use the provider key.' :
      'Proxy login: Bearer application token. Standard username/password login is not advertised by this deployment.';
    const selected = catalog()?.applications.find(item => item.id === element('connect-application-choice').value);
    element('connect-application-note').textContent = newApp ? '' : selected ?
      'Expires ' + new Date(selected.token_expires_at_epoch_ms).toLocaleString() + '. Use the token already configured in your app. If lost or expired, rotate explicitly in Clients; this flow does not retrieve or renew it.' : 'Select an available application.';
    element('connect-credential-fields').disabled = !['key', 'github', 'npm', 'x', 'alchemy', 'common', 'saved'].includes(connectionMethod) || !writable() || Boolean(checkpoint) ||
      newCredential && !workspace.ready('credentials') || connectionMethod === 'github' && !catalog()?.capabilities.github && !catalog()?.capabilities.github_app ||
      connectionMethod === 'npm' && !catalog()?.capabilities.npm || connectionMethod === 'x' && !xDestinationAvailable(catalog()) ||
      connectionMethod === 'alchemy' && !alchemyDestinationAvailable(catalog());
    element('connect-application-fields').disabled = saveOnly || !writable() || Boolean(checkpoint) || !credential() || newApp && !workspace.ready('applications');
    element('connect-access-fields').disabled = saveOnly || !writable() || Boolean(checkpoint) || !activePair() || newRule &&
      (!workspace.ready('access_rules') || !availableCredentialInputModes(catalog()).length ||
        (!gmail && !providerPreset && !availableResponseModes(catalog()).length) || !catalog()?.allowed_upstreams.length);
    const approvalDraft = {operation_bundle: common || element('connect-operation').value === 'exact' ? undefined : element('connect-operation').value,
      ...(xPost && element('connect-x-post-quota').value === 'daily' ? {daily_post_attempt_limit: 1} : {})};
    const approvalAvailable = operatorHostApprovalAvailable(catalog(), approvalDraft);
    element('connect-approval-group').hidden = !newRule || ecr;
    element('connect-approval-required').disabled = !newRule || !approvalAvailable && !element('connect-approval-required').checked;
    element('connect-approval-help').textContent = Object.hasOwn(approvalDraft, 'daily_post_attempt_limit') ?
      'Human approval cannot currently be combined with an X daily posting-attempt limit. Keep the quota, or explicitly choose a different restriction; neither is removed automatically.' : approvalAvailable ?
      'Host-trusted: server administrators can bypass it. Each first request stops with HTTP 428; after approval the client must explicitly retry exactly that request once. No automatic replay.' :
      'Host-trusted approvals are unavailable until this permission and the running proxy advertise matching support. Leave unchecked for ordinary permission-controlled access.';
    element('connect-review').disabled = newRule && (gmail && (!gmailAvailable(catalog(), credential()) || Boolean(gmailAgeProblemText) ||
      !['sdk', 'custom'].includes(element('connect-gmail-client').value) || gmailSdk && Boolean(gmailSdkProblem())) || github && !githubAvailable(catalog(), credential()) ||
      x && !xAvailable(catalog(), credential()) ||
      ecr && !ecrAvailable(catalog(), credential()) || common && !commonAppAvailable(catalog(), credential(), element('connect-operation').value) ||
      xPost && (!xPostAvailable(catalog(), credential()) || Boolean(xPostQuotaProblem)) ||
      alchemy && !alchemyAvailable(catalog(), credential(), element('connect-alchemy-chain').value) ||
      npm && (npmInstall ? !npmInstallAvailable(catalog(), credential()) || !npmInstallNewRuleAvailable(catalog(), selectedApplication) :
        npmPublish ? !npmPublishAvailable(catalog(), credential()) || !publishGrantAvailable() :
        !npmAvailable(catalog(), credential()) || !metadataGrantAvailable()));
  }
  function reviewCurrent() {
    return review && activePair() && catalog()?.revision === review.revision && catalog()?.policy.policy_hash === review.policyHash && supported(review.rule) &&
      (review.gmailClient !== 'sdk' || !gmailSdkProblem() && operatorExact(review.rule, {...gmailSdkRule(),
        ...(review.rule.approval_mode ? {approval_mode: review.rule.approval_mode} : {})})) &&
      (!isXRule(review.rule) || xCredentialReceiptMatches(credential(), review.xCredential)) &&
      (!isXPostRule(review.rule) || operatorExact(xAccountIdentity(credential()), review.xAccount)) &&
      (!isGithubAppCredential(credential()) || githubAppCredentialReceiptMatches(credential(), review.githubAppCredential)) &&
      (!isAlchemyRule(review.rule) || alchemyCredentialReceiptMatches(credential(), review.alchemyCredential));
  }
  function renderReview() {
    if (!review) return;
    const rows = [...operatorRuleCredentialRows(review.rule, credential()), ...operatorRuleRestrictions(review.rule), ...operatorApprovalRows(review.rule)];
    if (review.gmailClient === 'sdk') rows.unshift(['Gmail client', 'Official Gmail SDK · choose Go, Node.js or Python in client setup'],
      ['Public dummy, not a secret', 'The SDK sends the exact dummy below. The application token authenticates separately to the HTTPS proxy using standard username/password login.']);
    element('connect-review-details').replaceChildren(...rows.flatMap(([name, value]) => [textNode('dt', name), textNode('dd', value)]));
    if (reviewCurrent()) {
      const appName = operatorConnectResourceChoices(catalog().applications.filter(item => item.status === 'active'), [actionLabels.application]).find(item => item.id === selectedApplication).name;
      const credentialName = operatorConnectResourceChoices(catalog().credentials.filter(item => item.status === 'active'), [actionLabels.credential]).find(item => item.id === selectedCredential).name;
      element('connect-review-context').textContent = isNpmPublishRule(review.rule) ?
        `${appName} may use ${credentialName} to ${npmPublishReview(review.rule).replace(/^Publish/, 'publish')}` :
        `${appName} may use ${credentialName} only as follows.`;
    } else element('connect-review-context').textContent =
      'Saved state changed or a selected resource is unavailable. Go Back, verify your choices and Review access again. No grant was sent.';
    element('connect-grant').textContent = review.existing ? 'Use this saved rule' : 'Grant access';
    element('connect-grant').disabled = saveOnly || !writable() || Boolean(checkpoint) || !reviewCurrent();
  }
  function renderSetup() {
    const rule = matchingRules().find(item => item.id === selectedRule);
    const provider = catalog()?.credentials.find(item => item.id === selectedCredential);
    element('connect-provider-status').textContent = (!provider ? 'Provider status is unavailable; refresh saved state.' :
      provider.auth_type === 'google_oauth' ? provider.status === 'quarantined' ?
        'Google account: quarantined and unavailable for use. Provider revocation is not proven. This setup does not start consent or cleanup.' :
        'Google account: saved metadata only. This setup has not tested consent, token refresh or a Google request. ' +
          (catalog()?.capabilities.google_oauth ? 'Use Connect Google for a separate, explicit consent flow.' : 'Google account connection remains disabled here.') :
        isXOAuthCredential(provider) ? 'X account: saved consent identity. This page has not tested current provider entitlement or sent a post. Token refresh health requires observed evidence, not just a saved account.' :
        isGithubAppCredential(provider) ? 'GitHub App: saved installation and repository binding. Installation-token renewal is automatic; this page has not tested current refresh health or run a client.' :
        'Provider key: stored, not tested here.') +
      ' Application token: separate expiry. Rule: usable only after the proxy confirms the saved policy.';
    const active = writable() && activePair() && workspace.loaded() && rule?.enforcement === 'active' && application()?.access_status === 'active' && supported(rule);
    element('connect-activation').textContent = active ? 'Rule active in the proxy. Configure your client below; no upstream request has been tested here.' :
      !catalog() ? 'Status unavailable. Refresh saved state before using this setup.' : !activePair() || !rule ?
        'A selected credential, app token or rule is no longer available. Return to your choices or explicitly rotate an expired token in Clients.' :
        'Waiting for the proxy to confirm this exact saved rule and policy. No request has been tested. Refresh saved state if automatic observation has stopped.';
    element('connect-setup-slot').hidden = !active;
    if (open && step === 4) { proxy.mount(element('connect-setup-slot')); if (active) proxy.select(selectedApplication, selectedRule); }
  }
  function render() {
    renderInputs(); confirmCheckpoint(); renderForms(); renderReview(); renderGoogleAccount();
    const diagnostics = operatorDiagnosticResources(catalog());
    element('connect-diagnostics-option').hidden = saveOnly || !diagnostics.access_rules.size;
    element('connect-include-diagnostics').checked = includeDiagnostics;
    element('connect-include-diagnostics').disabled = !writable() || Boolean(checkpoint) || step !== 0 || connectionMethod === 'google';
    const saved = saveOnly && Boolean(savedCredential);
    const savedItem = catalog()?.credentials.find(item => item.id === savedCredential && item.status === 'active');
    element('connect-title').textContent = saveOnly ? 'Add credential' : 'Set up access';
    element('connect-intro').textContent = saveOnly ?
      'Save a provider account or key in Serverware. This does not create a client, issue a proxy token or grant any permissions.' :
      'Choose a credential, select the client that needs it, then review its permissions. A client is your script, agent or CI job; it gets a proxy token, never the provider secret.';
    if (open) {
      element('page-label').textContent = element('connect-title').textContent;
      document.title = element('connect-title').textContent + ' - Serverware operator workspace';
    }
    applications.mount(open && !saveOnly ? element('connect-token-slot') : null);
    element('connect-credential-saved').hidden = !saved;
    element('connect-credential-saved-summary').textContent = savedItem ?
      savedItem.name + ' is saved in Credentials. Provider request success has not been tested here.' :
      'The saved credential is no longer available. Review Credentials; no replacement credential was selected.';
    element('connect-saved-use').disabled = !writable() || Boolean(checkpoint) || !operatorCredentialCanSetUpAccess(savedItem, catalog());
    element('connect-saved-done').disabled = workspace.state.busy;
    const googleOpen = connectionMethod === 'google';
    element('connect-method-choice').hidden = connectionMethod !== null;
    element('connect-credential-form').hidden = !['key', 'github', 'npm', 'x', 'alchemy', 'common', 'saved'].includes(connectionMethod);
    element('connect-credential-heading').textContent = connectionMethod === 'common' ? 'Connect ' + (commonPreset()?.label || 'app') : connectionMethod === 'alchemy' ? 'Save an Alchemy API or access key' : connectionMethod === 'x' ? 'Save an X app-only bearer token' : connectionMethod === 'npm' ? 'Save an npm token' : connectionMethod === 'github' ? newGithubApp() ? 'Connect a GitHub App' : 'Save a GitHub token' : connectionMethod === 'key' ? 'Use an API key' : 'Use a saved credential';
    renderCommonPicker();
    element('connect-google-slot').hidden = !googleOpen;
    element('connect-method-change').hidden = connectionMethod === null || googleOpen;
    element('connect-method-change').disabled = !writable() || Boolean(checkpoint);
    element('connect-use-key').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials');
    element('connect-use-github').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') ||
      !catalog()?.capabilities.github && !catalog()?.capabilities.github_app;
    element('connect-use-npm').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') || !catalog()?.capabilities.npm;
    element('connect-use-x').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') || !xDestinationAvailable(catalog());
    element('connect-use-alchemy').disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials') || !alchemyDestinationAvailable(catalog());
    element('connect-alchemy-status').textContent = !catalog()?.capabilities.alchemy ?
      'Alchemy chain-status reads are not advertised by this deployment. A manual key is not a substitute for the JSON-RPC preset.' : !alchemyDestinationAvailable(catalog()) ?
      'Alchemy needs the exact mainnet or Sepolia origin approved in Proxy setup first. This page will not add destinations or restart services.' :
      'Alchemy: save a key, choose an app and explicitly select an approved chain. Only eth_chainId and eth_blockNumber; no transactions or arbitrary RPC. Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. This page has not tested your Alchemy credentials or provider entitlement.';
    element('connect-x-status').textContent = !catalog()?.capabilities.x ?
      'X app-only username lookup is not advertised by this deployment. No generic fallback or provider request is sent.' : !xDestinationAvailable(catalog()) ?
      'X username lookup needs the exact api.x.com destination approved in Proxy setup first. This page will not add it or restart services.' :
      'X: save an app-only bearer token, choose an app and allow one exact username lookup. No posting or user OAuth. Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. This page has not tested your X credentials or provider entitlement.';
    element('connect-npm-status').textContent = catalog()?.capabilities.npm_install ?
      'npm: installation is a separate explicit package/dependency allowlist, with metadata, tarballs and bulk audit. Existing metadata or publishing permissions are unchanged. No stock-client job or provider access is verified here.' : catalog()?.capabilities.npm_publish ?
      catalog().capabilities.npm_publish.destination_allowed && catalog().allowed_upstreams.includes(operatorNpm.origin) ?
        'npm: choose Read package metadata or Publish package for explicit package access. Publishing can be limited to daily UTC hours. This page has not tested the provider.' :
        'An npm token can be saved, but publishing cannot be granted until registry.npmjs.org is approved in Proxy setup.' :
      !catalog()?.capabilities.npm ? 'npm metadata lookup is not advertised by this deployment.' :
      catalog().capabilities.npm.destination_allowed && catalog().allowed_upstreams.includes(operatorNpm.origin) ?
        'npm: save one token and grant Read package metadata for named packages. npm view/pacote.manifest only; no install, publish, tarballs or npm audit. No provider lookup has been tested here.' :
        'An npm token can be saved, but metadata access cannot be granted until the operator approves registry.npmjs.org in deployment settings.';
    element('connect-github-status').textContent = catalog()?.capabilities.github_app ?
      githubAppDestinationAvailable(catalog()) ? 'GitHub: choose a personal access token or GitHub App, then grant repository-scoped issue permissions. App installation tokens renew automatically; personal access tokens do not.' :
        'Approve api.github.com in Proxy setup before verifying a GitHub App. No destination is added automatically. Personal access tokens can still be saved when advertised.' :
      !catalog()?.capabilities.github ? 'GitHub presets are not advertised by this deployment.' :
      catalog().capabilities.github.destination_allowed && catalog().allowed_upstreams.includes(operatorGithub.origin) ?
        'GitHub: save a personal access token and grant repository-scoped issue permissions. GitHub App connections are not advertised by this deployment.' :
        'A GitHub token can be saved, but access cannot be granted until the operator approves api.github.com in deployment settings.';
    element('connect-use-saved').disabled = !writable() || Boolean(checkpoint) || !catalog()?.credentials.some(item =>
      item.status === 'active' && (!isAwsCredential(item) || ecrAvailable(catalog(), item)) && (includeDiagnostics || !diagnostics.credentials.has(item.id)));
    element('connect-ecr-status').textContent = projectEcrCapability(catalog()?.capabilities.ecr_publication) ?
      'AWS ECR: save credentials in Credentials, choose Use with a client, and grant one exact account/region/repository/tag. Every staged image requires human approval before publication.' :
      'AWS credentials may be stored in Credentials. ECR publishing remains unavailable until the publication owner and matching proxy advertise readiness; a manual header key is not a substitute.';
    element('connect-use-saved').hidden = saveOnly;
    for (const id of ['connect-actions', 'connect-leave-help', 'connect-compatibility']) element(id).hidden = googleOpen;
    if (saveOnly) element('connect-compatibility').hidden = true;
    steps.forEach((name, index) => { element('connect-' + name + '-step').hidden = saved || index !== step || saveOnly && index !== 0; });
    element('connect-progress').textContent = saveOnly ? saved ? 'Credential saved · no access granted' : 'Save a credential · no access granted' : (step + 1) + ' of 5 · ' + labels[step];
    element('connect-back').hidden = step === 0 || step === 4;
    element('connect-back').disabled = workspace.state.busy || Boolean(checkpoint);
    element('connect-cancel').disabled = workspace.state.busy;
    element('connect-status-refresh').disabled = workspace.state.busy;
    element('connect-start-over').hidden = saveOnly ? !saved : step !== 4;
    element('connect-start-over').textContent = saveOnly ? 'Add another credential' : 'Set up another client';
    element('connect-start-over').disabled = workspace.state.busy || Boolean(checkpoint);
    const missingToken = selectedApplication && !applications.tokenFor(selectedApplication);
    element('connect-token-note').hidden = saveOnly || !missingToken;
    element('connect-token-note').textContent = 'This page does not hold this application’s one-time token. Use the token you already saved. If it was lost or cleared, explicitly rotate it in Clients; no token is retrieved or renewed by this flow.';
    if (!catalog()) element('connect-credential-secret').value = '';
    if (!catalog() || workspace.state.uncertain || !githubAppDestinationAvailable(catalog())) element('connect-github-private-key').value = '';
    if (!catalog() || workspace.state.uncertain || !xDestinationAvailable(catalog())) element('connect-x-secret').value = '';
    if (!catalog() || workspace.state.uncertain || !alchemyDestinationAvailable(catalog())) element('connect-alchemy-secret').value = '';
    if (checkpoint) message(checkpoint.message || 'Save received, but the exact resource is not yet confirmed in refreshed state. Refresh; do not submit again.');
    renderSetup();
  }

  element('connect-credential-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (saveOnly && savedCredential) return;
    if (newGithubApp()) {
      let body;
      try {
        if (step !== 0 || !writable() || checkpoint || !workspace.ready('credentials') ||
            !githubCreationAvailable() || !event.currentTarget.reportValidity()) return;
        const installationId = element('connect-github-installation-id').value;
        const submitted = {name: element('connect-credential-name').value.trim(), app_id: element('connect-github-app-id').value,
          ...(installationId === '' ? {} : {installation_id: installationId}),
          repository: {owner: element('connect-github-app-owner').value.trim(), name: element('connect-github-app-repo').value.trim()},
          issues_permission: element('connect-github-app-permission').value};
        if (!githubIdValid(submitted.app_id) || installationId !== '' && !githubIdValid(installationId) ||
            !githubRepositoryValid(submitted.repository) || !['read', 'write'].includes(submitted.issues_permission))
          throw operatorError('Enter a numeric App ID, an exact repository and a supported permission. Leave the optional installation ID blank or enter its canonical numeric ID. No request was sent.');
        body = {...submitted, private_key_pem: element('connect-github-private-key').value};
        element('connect-github-private-key').value = '';
        await workspace.mutate('credentials/github-app', body, 'connect-status',
          result => receipt(result, 'credentials', 'credential', submitted, 'github_app'));
      } catch (error) { message(operatorMessage(error)); }
      finally { element('connect-github-private-key').value = ''; if (body) body.private_key_pem = ''; render(); }
      return;
    }
    if (connectionMethod === 'alchemy') {
      let body;
      try {
        if (step !== 0 || !writable() || checkpoint || !workspace.ready('credentials') ||
            !alchemyDestinationAvailable(catalog()) || !event.currentTarget.reportValidity()) return;
        body = {name: element('connect-alchemy-name').value.trim(), secret: element('connect-alchemy-secret').value};
        element('connect-alchemy-secret').value = '';
        const name = body.name;
        await workspace.mutate('credentials/alchemy-key', body, 'connect-status', result => receipt(result, 'credentials', 'credential', name, 'alchemy'));
      } catch (error) { message(operatorMessage(error)); }
      finally { element('connect-alchemy-secret').value = ''; if (body) body.secret = ''; render(); }
      return;
    }
    if (connectionMethod === 'x') {
      let body;
      try {
        if (step !== 0 || !writable() || checkpoint || !workspace.ready('credentials') ||
            !xDestinationAvailable(catalog()) || !event.currentTarget.reportValidity()) return;
        body = {name: element('connect-x-name').value.trim(), secret: element('connect-x-secret').value};
        element('connect-x-secret').value = '';
        const name = body.name;
        await workspace.mutate('credentials/x-app-bearer', body, 'connect-status', result => receipt(result, 'credentials', 'credential', name, 'x'));
      } catch (error) { message(operatorMessage(error)); }
      finally { element('connect-x-secret').value = ''; if (body) body.secret = ''; render(); }
      return;
    }
    if (step !== 0 || !['key', 'github', 'npm', 'common', 'saved'].includes(connectionMethod) || !writable() || checkpoint || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-credential-choice').value;
    if (connectionMethod === 'saved') {
      if (saveOnly || !catalog().credentials.some(item => item.id === choice && operatorCredentialCanSetUpAccess(item, catalog()))) return;
      savedChoice = choice; selectedCredential = choice; selectedApplication = ''; selectedRule = ''; review = null; goto(1); return;
    }
    if (!workspace.ready('credentials') || connectionMethod === 'github' && !githubCreationAvailable() || connectionMethod === 'npm' && !catalog().capabilities.npm) return;
    if (connectionMethod === 'common' && !commonPreset()) return;
    const body = connectionMethod === 'common' ?
      {name: element('connect-credential-name').value.trim(), app_preset: commonPreset().id,
        auth_type: commonPreset().auth_type, header_name: commonPreset().header_name, secret: element('connect-credential-secret').value} : ['github', 'npm'].includes(connectionMethod) ?
      {name: element('connect-credential-name').value.trim(), secret: element('connect-credential-secret').value} :
      {name: element('connect-credential-name').value.trim(), auth_type: element('connect-credential-auth-type').value,
      header_name: element('connect-credential-auth-type').value === 'bearer' ? 'Authorization' : element('connect-credential-header-name').value.trim(), secret: element('connect-credential-secret').value};
    const provider = ['github', 'npm'].includes(connectionMethod) ? connectionMethod : null;
    const submitted = {revision: catalog().revision, ids: catalog().credentials.map(item => item.id),
      policy: {policy_hash: catalog().policy.policy_hash, sequence: catalog().policy.sequence},
      fields: {name: body.name, auth_type: provider ? 'bearer' : body.auth_type,
        header_name: provider ? 'Authorization' : body.header_name,
        connection_type: provider ? provider + '_token_v1' : null, provider_id: provider,
        app_preset: body.app_preset || null}};
    element('connect-credential-secret').value = '';
    await workspace.mutate(connectionMethod === 'npm' ? 'credentials/npm-token' : connectionMethod === 'github' ? 'credentials/github-token' : 'credentials', body, 'connect-status',
      result => keyCreationReceipt(result, submitted)); render();
  });
  element('connect-application-form').addEventListener('submit', async event => {
    event.preventDefault(); if (saveOnly || step !== 1 || !writable() || checkpoint || !credential() || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-application-choice').value;
    if (choice !== 'new') {
      const item = catalog().applications.find(item => item.id === choice && item.status === 'active');
      if (!validApp(item)) { message('This application token is expired or unavailable. Rotate explicitly in Clients, then refresh.'); return; }
      selectedApplication = choice; selectedRule = ''; review = null; goto(2); return;
    }
    const saved = await applications.create(element('connect-application-name').value.trim(), Number(element('connect-token-ttl').value), 'connect-status');
    if (saved) checkpoint = {collection: 'applications', ...saved};
    render();
  });
  function draftRule() {
    if (isAwsCredential(credential())) {
      const scope = Object.fromEntries(['registry_id', 'region', 'repository_name', 'image_tag'].map(key => [key, element('connect-ecr-' + key).value.trim()]));
      const rule = {...ecrRuleFields(scope), name: ('Publish ECR image · ' + scope.repository_name + ':' + scope.image_tag).slice(0, 128),
        application_id: selectedApplication, credential_id: selectedCredential};
      if (catalog().access_rules.some(item => item.status === 'active' && isEcrRule(item) && item.application_id === selectedApplication && item.region === scope.region))
        throw operatorError('This client already has an ECR permission in this region. Reuse it or explicitly revoke it; no ambiguous permission was created.');
      if (!supported(rule)) throw operatorError('ECR requires a ready publication owner, standard client proxy login, and this exact regional destination approved in Proxy setup: ' + ecrOrigin(scope.region));
      return rule;
    }
    if (isCommonAppCredential(credential())) {
      const preset = commonPreset(), operation = commonAppCreationOperations(preset).find(item => item.id === element('connect-operation').value);
      if (!operation || !commonAppAvailable(catalog(), credential(), operation.id))
        throw operatorError('Approve this app destination in Proxy setup before granting access. No destination or permission was changed.');
      const rule = {...commonAppRuleFields(preset, operation.id, commonAppScopeInputs(operation)),
        name: (preset.label + ' · ' + operation.label).slice(0, 128), application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('This app permission is unavailable. Refresh and review it again.');
      return rule;
    }
    if (isXOAuthCredential(credential())) {
      if (element('connect-operation').value !== operatorXPost.bundle) throw operatorError('Choose the advertised X text-post permission. No fallback grant was sent.');
      const rule = {...xPostRuleFields(), name: 'Publish text · ' + credential().provider_account,
        application_id: selectedApplication, credential_id: selectedCredential,
        ...xPostQuotaInput(element('connect-x-post-quota').value, element('connect-x-post-limit').value, catalog(), credential())};
      if (!supported(rule)) throw operatorError('The connected account or paired X posting permission is unavailable. No grant was sent.');
      return rule;
    }
    if (isAlchemyCredential(credential())) {
      if (element('connect-operation').value !== operatorAlchemy.bundle) throw operatorError('Choose the advertised Alchemy chain-status permission. No fallback grant was sent.');
      const chain = element('connect-alchemy-chain').value;
      const rule = {...alchemyRuleFields(chain), name: 'Read chain status · ' + chain,
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('Alchemy chain-status reads or this exact approved chain are unavailable. No grant was sent.');
      return rule;
    }
    if (isXCredential(credential())) {
      if (element('connect-operation').value !== operatorX.bundle) throw operatorError('Choose the advertised X username permission. No fallback grant was sent.');
      const username = element('connect-x-username').value;
      const rule = {...xRuleFields(username), name: 'Look up X username · ' + username,
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('X username lookup or its approved destination is unavailable. No grant was sent.');
      return rule;
    }
    if (isNpmCredential(credential())) {
      if (isNpmInstallRule({operation_bundle: element('connect-operation').value})) {
        if (!npmInstallNewRuleAvailable(catalog(), selectedApplication)) throw operatorError('An active registry permission conflicts. Revoke it explicitly before granting installation.');
        const rule = {...npmInstallRuleFields(npmPackageInput(element('connect-npm-packages').value)), name: 'Install packages and run npm audit',
          application_id: selectedApplication, credential_id: selectedCredential};
        if (!supported(rule)) throw operatorError('Installation or this exact dependency allowlist is unavailable. No grant was sent.');
        return rule;
      }
      if (isNpmPublishRule({operation_bundle: element('connect-operation').value})) {
        if (!publishGrantAvailable()) throw operatorError('An existing npm permission or overlapping registry rule conflicts. Reuse it or explicitly revoke it before a new grant.');
        const hours = element('connect-npm-publish-hours').value;
        if (!['any', 'window'].includes(hours)) throw operatorError('Choose any time or explicit daily UTC publishing hours.');
        const rule = {...npmPublishRuleFields(element('connect-npm-publish-package').value.trim(),
          element('connect-npm-publish-tag').value.trim(), hours === 'window' ?
            {start: element('connect-npm-publish-start').value, end: element('connect-npm-publish-end').value} : null),
          name: ('Publish package · ' + element('connect-npm-publish-package').value.trim()).slice(0, 128),
          application_id: selectedApplication, credential_id: selectedCredential};
        if (!supported(rule)) throw operatorError('Publishing or the selected package configuration is unavailable. No grant was sent.');
        return rule;
      }
      if (element('connect-operation').value !== operatorNpm.bundle) throw operatorError('Choose an advertised npm permission. No fallback grant was sent.');
      if (!metadataGrantAvailable()) throw operatorError('An existing npm permission or overlapping registry GET rule conflicts. Reuse the saved permission or explicitly revoke the conflict before a new grant.');
      const packages = npmPackageInput(element('connect-npm-packages').value);
      const rule = {...npmRuleFields(packages), name: 'Read package metadata',
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('npm metadata lookup or the selected packages are unavailable. No grant was sent.');
      return rule;
    }
    if (isGithubCredential(credential())) {
      const repository = {owner: element('connect-github-owner').value.trim(), name: element('connect-github-repo').value.trim()};
      if (isGithubAppCredential(credential()) && !operatorExact(repository, credential().github_app.repository))
        throw operatorError('This GitHub App connection is bound to its saved repository. No grant was sent.');
      const bundle = element('connect-operation').value;
      const rule = {...githubRuleFields(bundle, repository), name: (githubPermissionName(bundle) + ' · ' + repository.owner + '/' + repository.name).slice(0, 128),
        application_id: selectedApplication, credential_id: selectedCredential};
      if (!supported(rule)) throw operatorError('GitHub permissions or this repository configuration are unavailable. No grant was sent.');
      return rule;
    }
    if (element('connect-operation').value === operatorGmail.bundle) {
      const client = element('connect-gmail-client').value;
      if (!['sdk', 'custom'].includes(client)) throw operatorError('Choose the official Gmail SDK or an explicit custom HTTP client. No grant was sent.');
      if (client === 'sdk') {
        const problem = gmailSdkProblem();
        if (problem) throw operatorError(problem);
        return gmailSdkRule();
      }
      const ageProblem = gmailAgeProblem(); if (ageProblem) throw operatorError(ageProblem);
      const rule = {...gmailRuleFields(gmailAgeInput()), name: 'Read Gmail', application_id: selectedApplication, credential_id: selectedCredential,
        credential_input: element('connect-credential-input').value};
      if (rule.credential_input === 'replace_exact') rule.placeholder = element('connect-placeholder').value;
      if (!supported(rule)) throw operatorError('Read Gmail is unavailable for this account or credential-input choice. Refresh before granting access.');
      return rule;
    }
    if (element('connect-operation').value !== 'exact') throw operatorError('Choose a supported permission. No grant was sent.');
    const origin = element('connect-origin').value; const path = element('connect-path').value.trim();
    const methods = [...document.querySelectorAll('input[name="connect-method"]:checked')].map(input => input.value);
    const rule = {name: operatorPermissionName(element('connect-rule-name').value, methods, path), application_id: selectedApplication, credential_id: selectedCredential,
      upstream_url: origin.replace(/\/$/, '') + path,
      methods,
      credential_input: element('connect-credential-input').value, response_mode: element('connect-response-mode').value,
      response_fields: element('connect-response-mode').value === 'projected_json' ? fieldLines('connect-response-fields') : [],
      ...operatorRequestBodyInput(element('connect-request-body-mode').value, fieldLines('connect-request-fields'), catalog(), credential()),
      query_keys: fieldLines('connect-query-keys'), allowed_headers: fieldLines('connect-allowed-headers')};
    if (rule.credential_input === 'replace_exact') rule.placeholder = element('connect-placeholder').value;
    if (!catalog().allowed_upstreams.includes(origin) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        credential()?.legacy_upstream_origin && credential().legacy_upstream_origin !== origin || !supported(rule))
      throw operatorError('Choose an approved exact path and supported methods, content and credential-input choices. Exact dummy values must be printable ASCII with no outer spaces; selected-field responses require fields. Google permits only GET with no request body.');
    return rule;
  }
  element('connect-access-form').addEventListener('submit', event => {
    event.preventDefault(); if (saveOnly || step !== 2 || !writable() || checkpoint || !activePair() || !event.currentTarget.reportValidity()) return;
    try {
      const existing = element('connect-rule-choice').value !== 'new';
      const rule = existing ? matchingRules().find(item => item.id === element('connect-rule-choice').value) : draftRule();
      if (!existing && !isEcrRule(rule) && element('connect-approval-required').checked) {
        if (!operatorHostApprovalAvailable(catalog(), rule)) throw operatorError('Host-trusted approval is unavailable for this permission. Review the approval choice; no grant was sent.');
        rule.approval_mode = 'host_review_v1';
      }
      if (!supported(rule)) throw operatorError('The selected saved rule is unavailable or unsupported. Choose again; no permissions were changed.');
      review = {existing, rule: JSON.parse(JSON.stringify(rule)), revision: catalog().revision, policyHash: catalog().policy.policy_hash};
      if (!existing && isGmailRule(rule)) review.gmailClient = element('connect-gmail-client').value;
      if (isXRule(rule)) review.xCredential = xCredentialReceipt(credential(), credential().name);
      if (isXPostRule(rule)) review.xAccount = xAccountIdentity(credential());
      if (isAlchemyRule(rule)) review.alchemyCredential = alchemyCredentialReceipt(credential(), credential().name);
      if (isGithubAppCredential(credential())) review.githubAppCredential = githubAppCredentialReceipt(credential(), {name: credential().name, ...credential().github_app});
      message('Review the exact effective permissions before continuing.'); goto(3);
    } catch (error) { message(operatorMessage(error)); }
  });
  element('connect-grant').addEventListener('click', async () => {
    if (saveOnly || step !== 3 || !writable() || checkpoint || !reviewCurrent()) { renderReview(); return; }
    if (review.existing) {
      if (!matchingRules().some(item => item.id === review.rule.id)) return;
      selectedRule = review.rule.id; goto(4); return;
    }
    if (!workspace.ready('access_rules')) return;
    await workspace.mutate(isEcrRule(review.rule) ? 'access-rules/aws-ecr-publication' : isCommonAppRule(review.rule) ? 'access-rules/common-app' : isXPostRule(review.rule) ? 'access-rules/x-post' : isNpmInstallRule(review.rule) ? 'access-rules/npm-install' : isAlchemyRule(review.rule) ? 'access-rules/alchemy-chain-status' : isXRule(review.rule) ? 'access-rules/x-username' : isNpmPublishRule(review.rule) ? 'access-rules/npm-publish' : isNpmRule(review.rule) ? 'access-rules/npm-metadata' : isGithubRule(review.rule) ? 'access-rules/github' : isGmailRule(review.rule) ? 'access-rules/gmail-read' : 'access-rules',
      {...(isEcrRule(review.rule) ? ecrRulePayload(review.rule) : isCommonAppRule(review.rule) ? commonAppRulePayload(review.rule) : isXPostRule(review.rule) ? xPostRulePayload(review.rule) : isNpmInstallRule(review.rule) ? npmInstallRulePayload(review.rule) : isAlchemyRule(review.rule) ? alchemyRulePayload(review.rule) : isXRule(review.rule) ? xRulePayload(review.rule) : isNpmPublishRule(review.rule) ? npmPublishRulePayload(review.rule) : isNpmRule(review.rule) ? npmRulePayload(review.rule) : isGithubRule(review.rule) ? githubRulePayload(review.rule) : isGmailRule(review.rule) ? gmailRulePayload(review.rule) : review.rule),
        ...(review.rule.approval_mode ? {approval_mode: review.rule.approval_mode} : {})},
      'connect-status', result => receipt(result, 'access_rules', 'access_rule')); render();
  });
  for (const id of ['connect-credential-auth-type', 'connect-application-choice', 'connect-rule-choice', 'connect-operation', 'connect-gmail-client', 'connect-credential-input', 'connect-response-mode', 'connect-request-body-mode', 'connect-npm-publish-hours', 'connect-alchemy-chain', 'connect-approval-required'])
    element(id).addEventListener('change', render);
  element('connect-include-diagnostics').addEventListener('change', () => {
    if (!writable() || checkpoint || step !== 0 || connectionMethod === 'google') { render(); return; }
    includeDiagnostics = element('connect-include-diagnostics').checked;
    review = null; render();
  });
  element('connect-credential-choice').addEventListener('change', () => {
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    render();
  });
  element('connect-github-type').addEventListener('change', () => {
    element('connect-credential-secret').value = ''; element('connect-github-private-key').value = ''; review = null; render();
  });
  for (const [id, event] of [['connect-x-post-quota', 'change'], ['connect-x-post-limit', 'input']])
    element(id).addEventListener(event, () => { review = null; if (step === 3) step = 2; render(); });
  for (const [id, event] of [['connect-gmail-age-policy', 'change'], ['connect-gmail-age-days', 'input']])
    element(id).addEventListener(event, () => { review = null; if (step === 3) step = 2; render(); });
  function renderCommonPicker() {
    const presets = catalog()?.capabilities?.common_apps?.presets || [];
    element('connect-common-app-picker').hidden = !presets.length;
    const query = element('connect-common-search').value.trim().toLowerCase(), category = element('connect-common-category').value;
    const visible = presets.filter(item => (!query || [item.label, item.description, ...item.operations.map(op => op.label)].join(' ').toLowerCase().includes(query)) &&
      (category === 'all' || (['openai', 'anthropic', 'gemini', 'openrouter'].includes(item.id) ? 'ai' : 'services') === category));
    element('connect-common-empty').hidden = visible.length > 0;
    element('connect-common-apps').replaceChildren(...visible.map(item => {
      const button = textNode('button', item.label, 'secondary'); button.type = 'button'; button.dataset.commonApp = item.id;
      button.title = item.description + (item.destination_allowed ? '' : ' · Destination approval required in Proxy setup.');
      button.disabled = !writable() || Boolean(checkpoint) || !workspace.ready('credentials');
      button.addEventListener('click', () => {
        if (step !== 0 || connectionMethod !== null || !writable() || checkpoint || !workspace.ready('credentials')) return;
        element('connect-credential-secret').value = '';
        chooseCredentialTemplate({method: 'common', appPreset: item.id}); render(); focusCredentialSecret();
      });
      return button;
    }));
  }
  element('connect-common-search').addEventListener('input', renderCommonPicker);
  element('connect-common-category').addEventListener('change', renderCommonPicker);
  element('connect-common-scopes').addEventListener('input', () => { review = null; });
  for (const [id, method] of [['connect-use-key', 'key'], ['connect-use-github', 'github'], ['connect-use-npm', 'npm'], ['connect-use-x', 'x'], ['connect-use-alchemy', 'alchemy'], ['connect-use-saved', 'saved']]) element(id).addEventListener('click', () => {
    if (step !== 0 || connectionMethod !== null || !writable() || checkpoint || saveOnly && (savedCredential || method === 'saved')) return;
    if (method === 'github' && !catalog()?.capabilities.github && !catalog()?.capabilities.github_app) return;
    if (method === 'npm' && !catalog()?.capabilities.npm) return;
    if (method === 'x' && !xDestinationAvailable(catalog())) return;
    if (method === 'alchemy' && !alchemyDestinationAvailable(catalog())) return;
    element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    if (method === 'github') element('connect-github-type').value = catalog()?.capabilities.github ? 'github_token_v1' : 'github_app_v1';
    if (['github', 'npm'].includes(method)) element('connect-credential-secret').value = '';
    if (method === 'saved') { connectionMethod = method; element('connect-credential-choice').value = ''; }
    else chooseCredentialTemplate({method, ...(method === 'github' ? {githubType: element('connect-github-type').value} : {})});
    render(); if (method !== 'saved') focusCredentialSecret();
  });
  element('connect-method-change').addEventListener('click', () => {
    if (step !== 0 || !['key', 'github', 'npm', 'x', 'alchemy', 'common', 'saved'].includes(connectionMethod) || !writable() || checkpoint) return;
    if (saveOnly) { resetDraft(); location.hash = 'credentials'; requestAnimationFrame(() => element('credential-provider-search').focus()); return; }
    element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    if (['github', 'npm', 'common'].includes(connectionMethod)) element('connect-credential-secret').value = '';
    connectionMethod = null; render();
  });
  element('connect-request-fields').addEventListener('input', renderForms);
  element('connect-query-keys').addEventListener('input', renderForms);
  element('connect-back').addEventListener('click', () => { if (step > 0 && step < 4 && !workspace.state.busy && !checkpoint) { review = null; goto(step - 1); } });
  element('connect-status-refresh').addEventListener('click', () => workspace.refresh({manual: true}));
  function resetDraft() {
    pendingCredentialFocus = '';
    element('connect-approval-required').checked = false;
    selectedCredential = ''; selectedApplication = ''; selectedRule = ''; review = null; checkpoint = null; savedCredential = '';
    includeDiagnostics = false;
    connectionMethod = null; selectedCommonApp = ''; savedChoice = ''; beforeGoogle = null;
    for (const id of ['connect-credential-form', 'connect-application-form', 'connect-access-form']) element(id).reset();
    for (const id of ['connect-credential-choice', 'connect-application-choice', 'connect-rule-choice']) element(id).value = 'new';
    for (const id of ['connect-response-mode', 'connect-request-body-mode', 'connect-operation']) element(id).value = '';
    element('connect-restrictions').open = false;
    element('connect-x-post-quota').value = 'none'; element('connect-x-post-limit').value = '';
    element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; proxy.mount(null); step = 0;
  }
  element('connect-cancel').addEventListener('click', () => {
    if (workspace.state.busy || !window.confirm('Leave setup and discard this local draft? Saved credentials, clients and permissions remain. An uncertain operation must still be reconciled before another change. Any held one-time token remains under Clients until cleared or reloaded; save it before leaving the page. Nothing will be deleted, retried or renewed.')) return;
    resetDraft(); location.hash = saveOnly ? 'credentials' : 'overview';
  });
  element('connect-start-over').addEventListener('click', () => {
    if (saveOnly && savedCredential && writable() && !checkpoint) {
      resetDraft(); location.hash = 'credentials'; requestAnimationFrame(() => element('credential-provider-search').focus()); return;
    }
    if (workspace.state.busy || checkpoint || !window.confirm('Start another setup? Confirmed resources remain saved. Save any one-time token before creating another application. Nothing will be revoked.')) return;
    resetDraft(); message('Start a new setup. Existing resources and any held token remain.'); goto(0);
  });
  function selectCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id);
    if (!operatorCredentialCanSetUpAccess(item, catalog()) || !writable() || checkpoint) return false;
    resetDraft(); saveOnly = false; selectedCredential = id; connectionMethod = 'saved'; savedChoice = id;
    includeDiagnostics = operatorDiagnosticResources(catalog()).credentials.has(id);
    element('connect-credential-choice').value = ''; renderInputs(); element('connect-credential-choice').value = id;
    message('Saved credential selected. Choose a client; no token or permission was created.');
    location.hash = 'connect'; goto(1); return true;
  }
  element('connect-saved-use').addEventListener('click', () => {
    if (!selectCredential(savedCredential)) message('This exact saved credential is unavailable for setup. Review Credentials; no request was sent.');
  });
  element('connect-saved-done').addEventListener('click', () => { if (!workspace.state.busy) location.hash = 'credentials'; });
  element('connect-credential-form').addEventListener('invalid', event => {
    if (element('connect-credential-auth-details').contains(event.target)) element('connect-credential-auth-details').open = true;
    if (newGithubApp()) element('connect-github-private-key').value = '';
    if (connectionMethod === 'x') element('connect-x-secret').value = '';
    if (connectionMethod === 'alchemy') element('connect-alchemy-secret').value = '';
  }, true);
  window.addEventListener('hashchange', () => { element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; });
  window.addEventListener('pagehide', () => { element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; });
  workspace.subscribe(render);
  return {canAddCredential, addCredential(template) {
    if (!canAddCredential() || template !== undefined && !credentialTemplateAvailable(template)) return false;
    resetDraft(); saveOnly = true; message('Choose a provider or manual API key. Saving creates no client or permission.');
    if (template) { chooseCredentialTemplate(template); message('Save this credential. Client access can be configured later.'); }
    location.hash = 'connect'; goto(0); if (template) focusCredentialSecret(); return true;
  }, startSetup() {
    // Reopening the selected consent panel is navigation, not a new setup.
    // Keep its write hold and exact attempt intact until explicit completion
    // or Leave; otherwise the overview action strands a pending OAuth return.
    if (connectionMethod === 'google') return true;
    if (saveOnly) {
      if (!writable() || checkpoint) return false;
      resetDraft(); saveOnly = false; message('Choose a saved credential or add a new one, then select a client and review permissions.'); render();
    }
    return true;
  }, selectCredential, openGoogle({returning = false, credentialOnly = false} = {}) {
    if (connectionMethod === 'google') return true;
    if (!returning && (!writable() || checkpoint)) return false;
    element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    // A real OAuth return has no recoverable page-local draft. Opening consent
    // from this page is different: preserve its non-secret fields and mode so
    // Leave can return to the exact setup without recreating any resources.
    if (returning) { resetDraft(); saveOnly = true; }
    beforeGoogle = {step, method: connectionMethod, saveOnly, savedCredential};
    if (credentialOnly) { saveOnly = true; savedCredential = ''; }
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    connectionMethod = 'google'; goto(0); location.hash = 'connect'; return true;
  }, leaveGoogle() {
    if (connectionMethod !== 'google') return;
    const previous = beforeGoogle; beforeGoogle = null;
    connectionMethod = previous?.method || null; step = previous?.step || 0;
    saveOnly = previous?.saveOnly ?? saveOnly; savedCredential = previous?.savedCredential || '';
    render();
  }, selectGoogleCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id && value.status === 'active' && value.auth_type === 'google_oauth');
    return Boolean(item) && selectCredential(id);
  }, selectXAccountCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id && value.status === 'active' && isXOAuthCredential(value));
    return Boolean(item) && selectCredential(id);
  }, show(active) {
    open = active;
    if (!active) { element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; }
    if (!active || step !== 4) proxy.mount(null);
    render();
    if (active) focusVisibleCredential(); else pendingCredentialFocus = '';
  }};
}

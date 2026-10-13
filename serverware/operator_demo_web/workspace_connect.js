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
function createConnectView(workspace, applications, proxy) {
  const steps = ['credential', 'application', 'access', 'review', 'setup'];
  const labels = ['Account or API key', 'Application', 'Permission', 'Review access', 'Client setup'];
  const actionLabels = {credential: 'Choose a saved connection', application: 'Create a new application', rule: 'Grant a new permission'};
  let step = 0; let selectedCredential = ''; let selectedApplication = ''; let selectedRule = '';
  let review = null; let checkpoint = null; let open = false;
  let connectionMethod = null; let savedChoice = ''; let beforeGoogle = null;
  const catalog = () => workspace.state.catalog;
  const newGithubApp = () => connectionMethod === 'github' && element('connect-github-type').value === 'github_app_v1';
  const githubCreationAvailable = () => newGithubApp() ? githubAppDestinationAvailable(catalog()) :
    element('connect-github-type').value === 'github_token_v1' && Boolean(projectGithubCapability(catalog()?.capabilities.github));
  const writable = () => Boolean(catalog() && !workspace.state.busy && !workspace.state.uncertain);
  const credential = () => catalog()?.credentials.find(item => item.id === selectedCredential && item.status === 'active' && !isAwsCredential(item));
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
  function gmailSdkRule() {
    return {...gmailRuleFields(), name: 'Read Gmail', application_id: selectedApplication, credential_id: selectedCredential,
      credential_input: 'replace_exact', placeholder: 'Bearer serverware-gmail-placeholder-v1'};
  }
  function gmailSdkProblem() {
    if (!gmailAvailable(catalog(), credential()) || !catalog()?.allowed_upstreams.includes(operatorGmail.origin) ||
        !availableCredentialInputModes(catalog()).includes('replace_exact'))
      return 'The exact Read Gmail permission, approved Gmail destination and dummy-header replacement must all be advertised. No fallback permission is selected.';
    if (!projectApplicationProxyAuthenticationCapability(catalog()?.capabilities?.application_proxy_authentication))
      return 'Standard username/password proxy login is not advertised. The official SDK choice is unavailable; no login mode or permission is changed.';
    if (applicationProxyAuthentication(application()) !== 'basic_and_bearer_v1')
      return 'The official Gmail SDK needs standard username/password proxy login. In Applications, explicitly enable it for this app, then refresh here. No token or login mode is changed automatically.';
    if (!supported(gmailSdkRule())) return 'This account, application or Gmail permission is unavailable. Refresh and review again; no fallback grant is sent.';
    return '';
  }
  function confirmCheckpoint() {
    if (!checkpoint || !catalog() || workspace.state.busy || workspace.state.uncertain || catalog().revision < checkpoint.revision) return;
    if (checkpoint.xPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.xPolicyHash) {
      checkpoint.message = 'The saved X receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.alchemyPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.alchemyPolicyHash) {
      checkpoint.message = 'The saved Alchemy receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    if (checkpoint.githubAppPolicyHash && catalog().revision === checkpoint.revision && catalog().policy.policy_hash !== checkpoint.githubAppPolicyHash) {
      checkpoint.message = 'The saved GitHub App receipt and refreshed policy disagree. Inspect saved state; do not submit again.'; return;
    }
    const item = catalog()[checkpoint.collection].find(item => item.id === checkpoint.id && item.status === 'active');
    if (!item) { message('The exact saved resource cannot be confirmed. Review saved state; no repeat request was sent.'); return; }
    if (checkpoint.collection === 'credentials') {
      if (isAwsCredential(item)) { checkpoint.message = 'AWS credentials are stored only; no application setup is available.'; return; }
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
      element('connect-credential-choice').value = item.id; step = 1;
    }
    if (checkpoint.collection === 'applications') {
      if (!validApp(item)) { message('The saved application token is not currently valid. Use Applications for explicit rotation.'); return; }
      selectedApplication = item.id; selectedRule = ''; review = null; element('connect-application-choice').value = item.id; step = 2;
      renderInputs(); // The new app is now an exact confirmed pair; initialize its permission choice before showing access.
    }
    if (checkpoint.collection === 'access_rules') {
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
      selectedRule = item.id; step = 4;
    }
    checkpoint = null; message('Saved resource confirmed in the refreshed catalog.');
  }
  function receipt(result, collection, key, providerName, providerKind) {
    if (!result[key] || typeof result[key].id !== 'string' || !Number.isSafeInteger(result.revision))
      throw operatorError('The saved resource receipt was incomplete. Review saved state; do not repeat automatically.');
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
      ...(xMutation ? {xPolicyHash: result.policy.policy_hash} : {}),
      ...(alchemyMutation ? {alchemyPolicyHash: result.policy.policy_hash} : {}),
      ...(githubAppMutation ? {githubAppPolicyHash: result.policy.policy_hash} : {}),
      ...(collection === 'credentials' && githubAppMutation ? {githubApp: githubAppCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && xMutation ? {x: xCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && alchemyMutation ? {alchemy: alchemyCredentialReceipt(result[key], providerName)} : {}),
      ...(collection === 'credentials' && connectionMethod === 'github' && !githubAppMutation ? {github: true} : {}),
      ...(collection === 'credentials' && connectionMethod === 'npm' ? {npm: true} : {})};
  }
  function renderInputs() {
    const value = catalog(); if (!value) return;
    if (['key', 'github', 'npm', 'x', 'alchemy'].includes(connectionMethod)) choices('connect-credential-choice', [{id: 'new', name: 'New provider key'}], 'new');
    if (connectionMethod === 'saved') choices('connect-credential-choice', [{id: '', name: actionLabels.credential},
      ...operatorConnectResourceChoices(value.credentials.filter(item => item.status === 'active' && !isAwsCredential(item)), [actionLabels.credential])], savedChoice);
    choices('connect-application-choice', [...operatorConnectResourceChoices(value.applications.filter(item => item.status === 'active'), [actionLabels.application]), {id: 'new', name: actionLabels.application}], 'new');
    choices('connect-rule-choice', [{id: 'new', name: actionLabels.rule}, ...operatorConnectResourceChoices(matchingRules(), [actionLabels.rule])], 'new');
    choices('connect-origin', value.allowed_upstreams.map(origin => ({id: origin, name: origin})), value.allowed_upstreams[0]);
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
      const npmChoices = npm ? [...(npmAvailable(value, credential()) ? [{id: operatorNpm.bundle, name: 'Read package metadata'}] : []),
        ...(npmInstallAvailable(value, credential()) ? [{id: operatorNpmInstall.bundle, name: 'Install packages and run npm audit'}] : []),
        ...(value.capabilities.npm_publish && npmPublishAvailable(value, credential()) ? [{id: 'npm_publish_v1', name: 'Publish package'}] : [])] : [];
      choices('connect-operation', xPost ? xPostAvailable(value, credential()) ? [{id: operatorXPost.bundle, name: 'Publish text as this X account'}] : [] : alchemy ? alchemyAvailable(value, credential()) ? [{id: operatorAlchemy.bundle, name: 'Read chain status'}] : [] : x ? xAvailable(value, credential()) ? [{id: operatorX.bundle, name: 'Look up one X username'}] : [] : npm ? npmChoices : github ? githubAvailable(value, credential()) ?
        githubPermissionBundles(credential()).map(id => ({id, name: githubPermissionName(id)})) : [] :
        [...(bundle ? [{id: operatorGmail.bundle, name: 'Read Gmail'}] : []),
          {id: 'exact', name: 'Advanced: one exact endpoint'}], xPost ? operatorXPost.bundle : alchemy ? operatorAlchemy.bundle : x ? operatorX.bundle : npm ? npmChoices[0]?.id : github ? operatorGithub.read : bundle ? operatorGmail.bundle : 'exact');
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
    const newCredential = ['key', 'github', 'npm', 'x', 'alchemy'].includes(connectionMethod);
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
    const providerPreset = github || npm || x || xPost || alchemy;
    fields('connect-saved-choice', connectionMethod === 'saved'); fields('connect-credential-new', newCredential && !['x', 'alchemy'].includes(connectionMethod));
    fields('connect-x-new', connectionMethod === 'x');
    fields('connect-alchemy-new', connectionMethod === 'alchemy');
    fields('connect-application-new', newApp); fields('connect-rule-new', newRule);
    fields('connect-credential-auth-group', connectionMethod === 'key');
    fields('connect-github-type-group', connectionMethod === 'github');
    fields('connect-provider-secret-group', newCredential && !['x', 'alchemy'].includes(connectionMethod) && !newGithubApp());
    fields('connect-github-app-fields', newGithubApp());
    for (const option of element('connect-github-type').options) option.disabled = option.value === 'github_app_v1' ?
      !catalog()?.capabilities.github_app : !catalog()?.capabilities.github;
    element('connect-github-token-note').hidden = connectionMethod !== 'github' || newGithubApp();
    element('connect-npm-token-note').hidden = connectionMethod !== 'npm';
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
      {operation_bundle: element('connect-operation').value} : gmail && !(review && step >= 3) ? gmailRuleFields() : content);
    renderBasicCompatibility('connect', catalog(), credential());
    // Apply these last: nested legacy field renderers must not re-enable hidden
    // required controls. Switching permissions never clears the exact-rule draft.
    element('connect-operation-group').hidden = x || xPost || alchemy || !newRule || credential()?.auth_type !== 'google_oauth' && !gmail && !providerPreset;
    fields('connect-exact-destination', newRule && !gmail && !providerPreset);
    element('connect-credential-input-group').hidden = !newRule || providerPreset || gmailSdk;
    if (!newRule || providerPreset || gmailSdk) for (const input of element('connect-credential-input-group').querySelectorAll('input,select,textarea')) input.disabled = true;
    fields('connect-gmail-client-group', gmail);
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
    element('connect-x-post-summary').textContent = !xPost ? '' : !xPostAvailable(catalog(), credential()) ?
      'Posting is unavailable until this account, the approved destination and the current paired gate support the exact permission. No fallback grant is sent.' :
      'Publish text as ' + credential().provider_account + '. Text only; no media, replies, quotes or threads. Daily quotas are unavailable: this permission has no daily limit. Supply text only in your local client.';
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
      'Read Gmail: list messages, follow pagination and read individual messages in this account. No age restriction or optional content filtering. No sending, changes, attachments, history or Calendar. GET only, no request body; bounded JSON responses only.';
    element('connect-credential-next').textContent = newGithubApp() ? 'Save and verify GitHub App' : newCredential ? 'Save credential & continue' : 'Use saved credential';
    element('connect-credential-next').disabled = connectionMethod === 'github' && !githubCreationAvailable() ||
      !newCredential && !catalog()?.credentials.some(item => item.id === element('connect-credential-choice').value && item.status === 'active');
    element('connect-application-next').textContent = newApp ? 'Create app and show token' : 'Use this application';
    element('connect-application-proxy-default').textContent = newApplicationProxyAuthentication(catalog()).proxy_authentication ?
      'Proxy login: public application ID as username, this app’s token as password. Bearer also remains supported. Never use the provider key.' :
      'Proxy login: Bearer application token. Standard username/password login is not advertised by this deployment.';
    const selected = catalog()?.applications.find(item => item.id === element('connect-application-choice').value);
    element('connect-application-note').textContent = newApp ? '' : selected ?
      'Expires ' + new Date(selected.token_expires_at_epoch_ms).toLocaleString() + '. Use the token already configured in your app. If lost or expired, rotate explicitly in Applications; this flow does not retrieve or renew it.' : 'Select an available application.';
    element('connect-credential-fields').disabled = !['key', 'github', 'npm', 'x', 'alchemy', 'saved'].includes(connectionMethod) || !writable() || Boolean(checkpoint) ||
      newCredential && !workspace.ready('credentials') || connectionMethod === 'github' && !catalog()?.capabilities.github && !catalog()?.capabilities.github_app ||
      connectionMethod === 'npm' && !catalog()?.capabilities.npm || connectionMethod === 'x' && !xDestinationAvailable(catalog()) ||
      connectionMethod === 'alchemy' && !alchemyDestinationAvailable(catalog());
    element('connect-application-fields').disabled = !writable() || Boolean(checkpoint) || !credential() || newApp && !workspace.ready('applications');
    element('connect-access-fields').disabled = !writable() || Boolean(checkpoint) || !activePair() || newRule &&
      (!workspace.ready('access_rules') || !availableCredentialInputModes(catalog()).length ||
        (!gmail && !providerPreset && !availableResponseModes(catalog()).length) || !catalog()?.allowed_upstreams.length);
    element('connect-review').disabled = newRule && (gmail && (!gmailAvailable(catalog(), credential()) ||
      !['sdk', 'custom'].includes(element('connect-gmail-client').value) || gmailSdk && Boolean(gmailSdkProblem())) || github && !githubAvailable(catalog(), credential()) ||
      x && !xAvailable(catalog(), credential()) ||
      xPost && !xPostAvailable(catalog(), credential()) ||
      alchemy && !alchemyAvailable(catalog(), credential(), element('connect-alchemy-chain').value) ||
      npm && (npmInstall ? !npmInstallAvailable(catalog(), credential()) || !npmInstallNewRuleAvailable(catalog(), selectedApplication) :
        npmPublish ? !npmPublishAvailable(catalog(), credential()) || !publishGrantAvailable() :
        !npmAvailable(catalog(), credential()) || !metadataGrantAvailable()));
  }
  function reviewCurrent() {
    return review && activePair() && catalog()?.revision === review.revision && catalog()?.policy.policy_hash === review.policyHash && supported(review.rule) &&
      (review.gmailClient !== 'sdk' || !gmailSdkProblem() && operatorExact(review.rule, gmailSdkRule())) &&
      (!isXRule(review.rule) || xCredentialReceiptMatches(credential(), review.xCredential)) &&
      (!isXPostRule(review.rule) || operatorExact(xAccountIdentity(credential()), review.xAccount)) &&
      (!isGithubAppCredential(credential()) || githubAppCredentialReceiptMatches(credential(), review.githubAppCredential)) &&
      (!isAlchemyRule(review.rule) || alchemyCredentialReceiptMatches(credential(), review.alchemyCredential));
  }
  function renderReview() {
    if (!review) return;
    const rows = [...operatorRuleCredentialRows(review.rule, credential()), ...operatorRuleRestrictions(review.rule)];
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
    element('connect-grant').disabled = !writable() || Boolean(checkpoint) || !reviewCurrent();
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
        'A selected credential, app token or rule is no longer available. Return to your choices or explicitly rotate an expired token in Applications.' :
        'Waiting for the proxy to confirm this exact saved rule and policy. No request has been tested. Refresh saved state if automatic observation has stopped.';
    element('connect-setup-slot').hidden = !active;
    if (open && step === 4) { proxy.mount(element('connect-setup-slot')); if (active) proxy.select(selectedApplication, selectedRule); }
  }
  function render() {
    renderInputs(); confirmCheckpoint(); renderForms(); renderReview(); renderGoogleAccount();
    const googleOpen = connectionMethod === 'google';
    element('connect-method-choice').hidden = connectionMethod !== null;
    element('connect-credential-form').hidden = !['key', 'github', 'npm', 'x', 'alchemy', 'saved'].includes(connectionMethod);
    element('connect-credential-heading').textContent = connectionMethod === 'alchemy' ? 'Save an Alchemy API or access key' : connectionMethod === 'x' ? 'Save an X app-only bearer token' : connectionMethod === 'npm' ? 'Save an npm token' : connectionMethod === 'github' ? newGithubApp() ? 'Connect a GitHub App' : 'Save a GitHub token' : connectionMethod === 'key' ? 'Use an API key' : 'Use a saved connection';
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
      !catalog()?.capabilities.github ? 'GitHub presets are not advertised by this deployment. AWS presets are not available here.' :
      catalog().capabilities.github.destination_allowed && catalog().allowed_upstreams.includes(operatorGithub.origin) ?
        'GitHub: save a personal access token and grant repository-scoped issue permissions. GitHub App connections are not advertised by this deployment.' :
        'A GitHub token can be saved, but access cannot be granted until the operator approves api.github.com in deployment settings.';
    element('connect-use-saved').disabled = !writable() || Boolean(checkpoint) || !catalog()?.credentials.some(item => item.status === 'active' && !isAwsCredential(item));
    for (const id of ['connect-actions', 'connect-leave-help', 'connect-compatibility']) element(id).hidden = googleOpen;
    steps.forEach((name, index) => { element('connect-' + name + '-step').hidden = index !== step; });
    element('connect-progress').textContent = (step + 1) + ' of 5 · ' + labels[step];
    element('connect-back').hidden = step === 0 || step === 4;
    element('connect-back').disabled = workspace.state.busy || Boolean(checkpoint);
    element('connect-cancel').disabled = workspace.state.busy;
    element('connect-status-refresh').disabled = workspace.state.busy;
    element('connect-start-over').hidden = step !== 4;
    element('connect-start-over').disabled = workspace.state.busy || Boolean(checkpoint);
    const missingToken = selectedApplication && !applications.tokenFor(selectedApplication);
    element('connect-token-note').hidden = !missingToken;
    element('connect-token-note').textContent = 'This page does not hold this application’s one-time token. Use the token you already saved. If it was lost or cleared, explicitly rotate it in Applications; no token is retrieved or renewed by this flow.';
    if (!catalog()) element('connect-credential-secret').value = '';
    if (!catalog() || workspace.state.uncertain || !githubAppDestinationAvailable(catalog())) element('connect-github-private-key').value = '';
    if (!catalog() || workspace.state.uncertain || !xDestinationAvailable(catalog())) element('connect-x-secret').value = '';
    if (!catalog() || workspace.state.uncertain || !alchemyDestinationAvailable(catalog())) element('connect-alchemy-secret').value = '';
    if (checkpoint) message(checkpoint.message || 'Save received, but the exact resource is not yet confirmed in refreshed state. Refresh; do not submit again.');
    renderSetup();
  }

  element('connect-credential-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (newGithubApp()) {
      let body;
      try {
        if (step !== 0 || !writable() || checkpoint || !workspace.ready('credentials') ||
            !githubCreationAvailable() || !event.currentTarget.reportValidity()) return;
        const submitted = {name: element('connect-credential-name').value.trim(), app_id: element('connect-github-app-id').value,
          installation_id: element('connect-github-installation-id').value,
          repository: {owner: element('connect-github-app-owner').value.trim(), name: element('connect-github-app-repo').value.trim()},
          issues_permission: element('connect-github-app-permission').value};
        if (!githubIdValid(submitted.app_id) || !githubIdValid(submitted.installation_id) ||
            !githubRepositoryValid(submitted.repository) || !['read', 'write'].includes(submitted.issues_permission))
          throw operatorError('Enter canonical numeric App and installation IDs, an exact repository and a supported permission. No request was sent.');
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
    if (step !== 0 || !['key', 'github', 'npm', 'saved'].includes(connectionMethod) || !writable() || checkpoint || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-credential-choice').value;
    if (connectionMethod === 'saved') {
      if (!catalog().credentials.some(item => item.id === choice && item.status === 'active' && !isAwsCredential(item))) return;
      savedChoice = choice; selectedCredential = choice; selectedApplication = ''; selectedRule = ''; review = null; goto(1); return;
    }
    if (!workspace.ready('credentials') || connectionMethod === 'github' && !githubCreationAvailable() || connectionMethod === 'npm' && !catalog().capabilities.npm) return;
    const body = ['github', 'npm'].includes(connectionMethod) ?
      {name: element('connect-credential-name').value.trim(), secret: element('connect-credential-secret').value} :
      {name: element('connect-credential-name').value.trim(), auth_type: element('connect-credential-auth-type').value,
      header_name: element('connect-credential-auth-type').value === 'bearer' ? 'Authorization' : element('connect-credential-header-name').value.trim(), secret: element('connect-credential-secret').value};
    element('connect-credential-secret').value = '';
    await workspace.mutate(connectionMethod === 'npm' ? 'credentials/npm-token' : connectionMethod === 'github' ? 'credentials/github-token' : 'credentials', body, 'connect-status',
      result => receipt(result, 'credentials', 'credential')); render();
  });
  element('connect-application-form').addEventListener('submit', async event => {
    event.preventDefault(); if (step !== 1 || !writable() || checkpoint || !credential() || !event.currentTarget.reportValidity()) return;
    const choice = element('connect-application-choice').value;
    if (choice !== 'new') {
      const item = catalog().applications.find(item => item.id === choice && item.status === 'active');
      if (!validApp(item)) { message('This application token is expired or unavailable. Rotate explicitly in Applications, then refresh.'); return; }
      selectedApplication = choice; selectedRule = ''; review = null; goto(2); return;
    }
    const saved = await applications.create(element('connect-application-name').value.trim(), Number(element('connect-token-ttl').value), 'connect-status');
    if (saved) checkpoint = {collection: 'applications', ...saved};
    render();
  });
  function draftRule() {
    if (isXOAuthCredential(credential())) {
      if (element('connect-operation').value !== operatorXPost.bundle) throw operatorError('Choose the advertised X text-post permission. No fallback grant was sent.');
      const rule = {...xPostRuleFields(), name: 'Publish text · ' + credential().provider_account,
        application_id: selectedApplication, credential_id: selectedCredential};
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
      const rule = {...gmailRuleFields(), name: 'Read Gmail', application_id: selectedApplication, credential_id: selectedCredential,
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
    event.preventDefault(); if (step !== 2 || !writable() || checkpoint || !activePair() || !event.currentTarget.reportValidity()) return;
    try {
      const existing = element('connect-rule-choice').value !== 'new';
      const rule = existing ? matchingRules().find(item => item.id === element('connect-rule-choice').value) : draftRule();
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
    if (step !== 3 || !writable() || checkpoint || !reviewCurrent()) { renderReview(); return; }
    if (review.existing) {
      if (!matchingRules().some(item => item.id === review.rule.id)) return;
      selectedRule = review.rule.id; goto(4); return;
    }
    if (!workspace.ready('access_rules')) return;
    await workspace.mutate(isXPostRule(review.rule) ? 'access-rules/x-post' : isNpmInstallRule(review.rule) ? 'access-rules/npm-install' : isAlchemyRule(review.rule) ? 'access-rules/alchemy-chain-status' : isXRule(review.rule) ? 'access-rules/x-username' : isNpmPublishRule(review.rule) ? 'access-rules/npm-publish' : isNpmRule(review.rule) ? 'access-rules/npm-metadata' : isGithubRule(review.rule) ? 'access-rules/github' : isGmailRule(review.rule) ? 'access-rules/gmail-read' : 'access-rules',
      isXPostRule(review.rule) ? xPostRulePayload(review.rule) : isNpmInstallRule(review.rule) ? npmInstallRulePayload(review.rule) : isAlchemyRule(review.rule) ? alchemyRulePayload(review.rule) : isXRule(review.rule) ? xRulePayload(review.rule) : isNpmPublishRule(review.rule) ? npmPublishRulePayload(review.rule) : isNpmRule(review.rule) ? npmRulePayload(review.rule) : isGithubRule(review.rule) ? githubRulePayload(review.rule) : isGmailRule(review.rule) ? gmailRulePayload(review.rule) : {...review.rule},
      'connect-status', result => receipt(result, 'access_rules', 'access_rule')); render();
  });
  for (const id of ['connect-credential-auth-type', 'connect-application-choice', 'connect-rule-choice', 'connect-operation', 'connect-gmail-client', 'connect-credential-input', 'connect-response-mode', 'connect-request-body-mode', 'connect-npm-publish-hours', 'connect-alchemy-chain'])
    element(id).addEventListener('change', render);
  element('connect-credential-choice').addEventListener('change', () => {
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    render();
  });
  element('connect-github-type').addEventListener('change', () => {
    element('connect-credential-secret').value = ''; element('connect-github-private-key').value = ''; review = null; render();
  });
  for (const [id, method] of [['connect-use-key', 'key'], ['connect-use-github', 'github'], ['connect-use-npm', 'npm'], ['connect-use-x', 'x'], ['connect-use-alchemy', 'alchemy'], ['connect-use-saved', 'saved']]) element(id).addEventListener('click', () => {
    if (step !== 0 || connectionMethod !== null || !writable() || checkpoint) return;
    if (method === 'github' && !catalog()?.capabilities.github && !catalog()?.capabilities.github_app) return;
    if (method === 'npm' && !catalog()?.capabilities.npm) return;
    if (method === 'x' && !xDestinationAvailable(catalog())) return;
    if (method === 'alchemy' && !alchemyDestinationAvailable(catalog())) return;
    element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    if (method === 'github') element('connect-github-type').value = catalog()?.capabilities.github ? 'github_token_v1' : 'github_app_v1';
    if (['github', 'npm'].includes(method)) element('connect-credential-secret').value = '';
    connectionMethod = method;
    element('connect-credential-choice').value = ''; render();
  });
  element('connect-method-change').addEventListener('click', () => {
    if (step !== 0 || !['key', 'github', 'npm', 'x', 'alchemy', 'saved'].includes(connectionMethod) || !writable() || checkpoint) return;
    element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    if (['github', 'npm'].includes(connectionMethod)) element('connect-credential-secret').value = '';
    connectionMethod = null; render();
  });
  element('connect-request-fields').addEventListener('input', renderForms);
  element('connect-query-keys').addEventListener('input', renderForms);
  element('connect-back').addEventListener('click', () => { if (step > 0 && step < 4 && !workspace.state.busy && !checkpoint) { review = null; goto(step - 1); } });
  element('connect-status-refresh').addEventListener('click', () => workspace.refresh({manual: true}));
  function resetDraft() {
    selectedCredential = ''; selectedApplication = ''; selectedRule = ''; review = null; checkpoint = null;
    connectionMethod = null; savedChoice = ''; beforeGoogle = null;
    for (const id of ['connect-credential-form', 'connect-application-form', 'connect-access-form']) element(id).reset();
    for (const id of ['connect-credential-choice', 'connect-application-choice', 'connect-rule-choice']) element(id).value = 'new';
    for (const id of ['connect-response-mode', 'connect-request-body-mode', 'connect-operation']) element(id).value = '';
    element('connect-restrictions').open = false;
    element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; proxy.mount(null); step = 0;
  }
  element('connect-cancel').addEventListener('click', () => {
    if (workspace.state.busy || !window.confirm('Leave setup and discard this local draft? Saved credentials, applications and access rules remain. An uncertain operation must still be reconciled before another change. Any held one-time token remains under Applications until cleared or reloaded; save it before leaving the page. Nothing will be deleted, retried or renewed.')) return;
    resetDraft(); location.hash = 'overview';
  });
  element('connect-start-over').addEventListener('click', () => {
    if (workspace.state.busy || checkpoint || !window.confirm('Start another setup? Confirmed resources remain saved. Save any one-time token before creating another application. Nothing will be revoked.')) return;
    resetDraft(); message('Start a new setup. Existing resources and any held token remain.'); goto(0);
  });
  element('connect-credential-form').addEventListener('invalid', () => {
    if (newGithubApp()) element('connect-github-private-key').value = '';
    if (connectionMethod === 'x') element('connect-x-secret').value = '';
    if (connectionMethod === 'alchemy') element('connect-alchemy-secret').value = '';
  }, true);
  window.addEventListener('hashchange', () => { element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; });
  window.addEventListener('pagehide', () => { element('connect-credential-secret').value = ''; element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; });
  workspace.subscribe(render);
  return {openGoogle({returning = false} = {}) {
    if (connectionMethod === 'google') return true;
    if (!returning && (!writable() || checkpoint)) return false;
    element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = '';
    beforeGoogle = {step, method: connectionMethod};
    if (connectionMethod === 'saved') savedChoice = element('connect-credential-choice').value;
    connectionMethod = 'google'; goto(0); location.hash = 'connect'; return true;
  }, leaveGoogle() {
    if (connectionMethod !== 'google') return;
    const previous = beforeGoogle; beforeGoogle = null;
    connectionMethod = previous?.method || null; step = previous?.step || 0;
    render();
  }, selectGoogleCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id && value.status === 'active' && value.auth_type === 'google_oauth');
    if (!item || !writable() || checkpoint) return false;
    resetDraft(); selectedCredential = id; connectionMethod = 'saved'; savedChoice = id;
    element('connect-credential-choice').value = ''; renderInputs(); element('connect-credential-choice').value = id;
    message('Saved Google account selected. Choose an application; no access has been granted.'); goto(1); return true;
  }, selectXAccountCredential(id) {
    const item = catalog()?.credentials.find(value => value.id === id && value.status === 'active' && isXOAuthCredential(value));
    if (!item || !writable() || checkpoint) return false;
    resetDraft(); selectedCredential = id; connectionMethod = 'saved'; savedChoice = id;
    element('connect-credential-choice').value = ''; renderInputs(); element('connect-credential-choice').value = id;
    message('Saved X account selected. Choose an application; no posting permission has been granted.');
    location.hash = 'connect'; goto(1); return true;
  }, show(active) {
    open = active;
    if (!active) { element('connect-x-secret').value = ''; element('connect-alchemy-secret').value = ''; element('connect-github-private-key').value = ''; }
    if (!active && ['github', 'npm'].includes(connectionMethod)) element('connect-credential-secret').value = '';
    applications.mount(active ? element('connect-token-slot') : null);
    if (!active || step !== 4) proxy.mount(null);
    render();
  }};
}

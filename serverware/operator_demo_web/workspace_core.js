// Public catalog state and transport only. Provider secrets and client tokens do
// not belong in this state. All resource views share one explicit mutation gate.
const operatorMethods = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
// A typed provider permission is not a generic response-mode alias. Keep the
// closed source contract here; never infer a bundle from a URL or display name.
const operatorGmail = Object.freeze({bundle: 'gmail_read_v1', origin: 'https://gmail.googleapis.com',
  path: '/gmail/v1/users/me/messages', response: 'gmail_read_json_v1',
  queries: ['alt', 'format', 'includeSpamTrash', 'labelIds', 'maxResults', 'metadataHeaders', 'pageToken', 'prettyPrint', 'q'],
  headers: ['accept', 'user-agent', 'x-goog-api-client'], legacyHeaders: ['accept', 'accept-encoding', 'user-agent', 'x-goog-api-client']});
function operatorExact(value, expected) {
  if (Array.isArray(expected)) return Array.isArray(value) && value.length === expected.length && expected.every((item, i) => operatorExact(value[i], item));
  if (expected && typeof expected === 'object') return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === Object.keys(expected).length && Object.keys(expected).every(key => Object.hasOwn(value, key) && operatorExact(value[key], expected[key]));
  return value === expected;
}
function operatorGmailDescriptor() {
  return {operation_bundle: operatorGmail.bundle, create_path: '/api/operator-demo/access-rules/gmail-read',
    credential_type: 'google_oauth', permission_preset: 'gmail_readonly', api_origin: operatorGmail.origin,
    methods: ['GET'], paths: [operatorGmail.path, operatorGmail.path + '/{message_id}'], query_mode: 'orderedFormV1',
    age_policy: {mode: 'unrestricted'}, response_mode: operatorGmail.response,
    response_contract: {mode: 'gmailReadJsonV1', body_presence: 'required', content_types: ['application/json'],
      success_status_codes: [200], error_status_codes: [400, 401, 403, 404, 429, 500, 502, 503, 504],
      max_body_bytes: 1048576, max_error_body_bytes: 65536, unlisted_header_policy: 'discardUnselectedV1'}};
}
function projectOperationBundles(value, google) {
  if (value === undefined) return []; // Old catalog: no authority to create a bundle.
  if (!Array.isArray(value) || value.length > 1 || value.some(item => !google || !operatorExact(item, operatorGmailDescriptor())))
    throw operatorError('Operation capability metadata is unsupported. Refresh before making changes.');
  return value.map(() => operatorGmailDescriptor());
}
function isGmailRule(rule) { return rule?.operation_bundle === operatorGmail.bundle; }
function isGithubAppCredential(credential) { return credential?.connection_type === 'github_app_v1'; }
function isGithubCredential(credential) { return ['github_token_v1', 'github_app_v1'].includes(credential?.connection_type); }
function isGithubRule(rule) { return ['github_issues_read_v1', 'github_issues_write_v1'].includes(rule?.operation_bundle); }
function isNpmCredential(credential) { return credential?.connection_type === 'npm_token_v1'; }
function isNpmRule(rule) { return rule?.operation_bundle === 'npm_metadata_read_v1'; }
function isNpmPublishRule(rule) { return rule?.operation_bundle === 'npm_publish_v1'; }
function isNpmInstallRule(rule) { return rule?.operation_bundle === 'npm_install_v1'; }
function isXCredential(credential) { return credential?.connection_type === 'x_app_bearer_v1'; }
function isXRule(rule) { return rule?.operation_bundle === 'x_username_read_v1'; }
function isXOAuthCredential(credential) { return credential?.auth_type === 'x_oauth' && credential?.connection_type === 'x_user_oauth_v1'; }
function isXPostRule(rule) { return rule?.operation_bundle === 'x_text_post_v1'; }
function isAlchemyCredential(credential) { return credential?.connection_type === 'alchemy_key_v1'; }
function isAlchemyRule(rule) { return rule?.operation_bundle === 'alchemy_chain_status_read_v1'; }
function isAwsCredential(credential) { return credential?.auth_type === 'aws_sigv4_v1' || credential?.connection_type === 'aws_sigv4_v1'; }
function gmailAvailable(catalog, credential) {
  return credential?.status === 'active' && credential.auth_type === 'google_oauth' &&
    credential.permission_preset === 'gmail_readonly' && Boolean(catalog?.capabilities.google_oauth) &&
    catalog.capabilities.operation_bundles?.some(item => operatorExact(item, operatorGmailDescriptor()));
}
function gmailRuleFields() {
  return {operation_bundle: operatorGmail.bundle, age_policy: {mode: 'unrestricted'}, query_mode: 'orderedFormV1',
    upstream_url: operatorGmail.origin + operatorGmail.path, methods: ['GET'], request_fields: [], response_fields: [],
    query_keys: [...operatorGmail.queries], allowed_headers: [...operatorGmail.headers], response_mode: operatorGmail.response};
}
function gmailRuleValid(rule, credential) {
  const expected = gmailRuleFields(); delete expected.query_mode;
  if (!Object.hasOwn(rule, 'query_mode')) expected.allowed_headers = [...operatorGmail.legacyHeaders];
  return credential?.auth_type === 'google_oauth' && credential.header_name === 'Authorization' &&
    credential.permission_preset === 'gmail_readonly' && !Object.hasOwn(rule, 'request_body_mode') &&
    (!Object.hasOwn(rule, 'query_mode') || rule.query_mode === 'orderedFormV1') &&
    Object.entries(expected).every(([key, value]) => operatorExact(rule[key], value));
}
function gmailRulePayload(rule) {
  return {name: rule.name, application_id: rule.application_id, credential_id: rule.credential_id,
    operation_bundle: operatorGmail.bundle, age_policy: {mode: 'unrestricted'}, credential_input: rule.credential_input,
    ...(rule.credential_input === 'replace_exact' ? {placeholder: rule.placeholder} : {})};
}
const operatorResponseModes = Object.freeze({unfiltered_json_or_empty_v2: 'Keep JSON content or empty response',
  unfiltered_json_or_empty_v1: 'Keep JSON responses and empty 204',
  unfiltered_json: 'Do not filter response content (JSON)',
  projected_json: 'Only return selected JSON fields'});
function operatorResponseKeepsJson(mode) { return Object.hasOwn(operatorResponseModes, mode) && mode !== 'projected_json'; }
function operatorResponseAllowsEmpty204(mode) { return ['unfiltered_json_or_empty_v1', 'unfiltered_json_or_empty_v2'].includes(mode); }
function availableResponseModes(catalog) {
  const advertised = catalog?.capabilities?.response_modes;
  return Array.isArray(advertised) ? Object.keys(operatorResponseModes).filter(mode => advertised.includes(mode)) : [];
}
function responseFormChoices(catalog, current) {
  const modes = availableResponseModes(catalog);
  // Compatibility generations are persisted contracts, not operator choices.
  // Retain an advertised draft exactly; only a fresh choice gets the default.
  const whole = modes.includes(current) && operatorResponseKeepsJson(current) ? current : modes.find(operatorResponseKeepsJson);
  return [...(whole ? [{id: whole, name: 'Do not filter response content'}] : []),
    ...(modes.includes('projected_json') ? [{id: 'projected_json', name: 'Only return selected JSON fields'}] : [])];
}
function operatorPermissionName(value, methods, path) {
  return value.trim() || (methods.join(', ') + ' ' + path).slice(0, 128).trim();
}
const operatorCredentialInputModes = Object.freeze({insert: 'Add credential automatically', replace_exact: 'Replace a dummy header value'});
function availableCredentialInputModes(catalog) {
  const advertised = catalog?.capabilities?.credential_input_modes;
  return Array.isArray(advertised) ? Object.keys(operatorCredentialInputModes).filter(mode => advertised.includes(mode)) : [];
}
// legacy_fields is a form choice, never an API enum. Omission retains the old
// declared-field/no-body contract; a capability cannot broaden a saved rule.
const operatorRequestBodyChoices = Object.freeze({preserve_json_v1: 'Keep JSON request content',
  legacy_fields: 'Restrict JSON fields (empty blocks bodies)'});
function availableRequestBodyChoices(catalog, credential) {
  if (isAwsCredential(credential)) return [];
  const advertised = catalog?.capabilities?.request_body_modes;
  return [...(credential && credential.auth_type !== 'google_oauth' && Array.isArray(advertised) &&
    advertised.includes('preserve_json_v1') ? ['preserve_json_v1'] : []), 'legacy_fields'];
}
function operatorRequestBodyInput(choice, requestFields, catalog, credential) {
  if (!availableRequestBodyChoices(catalog, credential).includes(choice) ||
      choice === 'preserve_json_v1' && requestFields.length || credential?.auth_type === 'google_oauth' && requestFields.length)
    throw operatorError('Choose a supported request-body mode. Clear explicit field restrictions before preserving JSON. Google permits GET with no body only.');
  return {request_fields: requestFields, ...(choice === 'preserve_json_v1' ? {request_body_mode: choice} : {})};
}
function operatorRuleContentValid(rule, credential) {
  if (isAwsCredential(credential)) return false; // Stored tuple is not a header credential or a grant.
  if (rule && ['quota', 'daily_quota'].some(key => Object.hasOwn(rule, key))) return false;
  if (rule && !isAlchemyRule(rule) && Object.hasOwn(rule, 'chain')) return false;
  if (rule && !isXRule(rule) && Object.hasOwn(rule, 'username')) return false;
  if (rule && !isNpmPublishRule(rule) && ['package', 'tag', 'publishing_window'].some(key => Object.hasOwn(rule, key))) return false;
  if (rule && Object.hasOwn(rule, 'operation_bundle')) return isGmailRule(rule) ? gmailRuleValid(rule, credential) :
    isXPostRule(rule) ? xPostRuleValid(rule, credential) :
    isAlchemyRule(rule) ? alchemyRuleValid(rule, credential) :
    isXRule(rule) ? xRuleValid(rule, credential) :
    isNpmPublishRule(rule) ? npmPublishRuleValid(rule, credential) :
    isNpmInstallRule(rule) ? npmInstallRuleValid(rule, credential) :
    isNpmRule(rule) ? npmRuleValid(rule, credential) :
    typeof isGithubRule === 'function' && isGithubRule(rule) && githubRuleValid(rule, credential);
  if (['github_token_v1', 'github_app_v1', 'npm_token_v1', 'x_app_bearer_v1', 'x_user_oauth_v1', 'alchemy_key_v1'].includes(credential?.connection_type) || rule && ['age_policy', 'query_mode', 'repository', 'packages', 'package', 'tag', 'publishing_window'].some(key => Object.hasOwn(rule, key))) return false;
  if (!rule || !['methods', 'request_fields', 'response_fields', 'query_keys', 'allowed_headers'].every(name =>
      Array.isArray(rule[name]) && rule[name].every(value => typeof value === 'string')) ||
      !rule.methods.length || rule.methods.some(method => !operatorMethods.includes(method)) ||
      !Object.hasOwn(operatorResponseModes, rule.response_mode) ||
      (rule.response_mode === 'projected_json' ? !rule.response_fields.length : rule.response_fields.length)) return false;
  if (Object.hasOwn(rule, 'request_body_mode') && (rule.request_body_mode !== 'preserve_json_v1' || rule.request_fields.length)) return false;
  return credential?.auth_type !== 'google_oauth' || !Object.hasOwn(rule, 'request_body_mode') &&
    !rule.request_fields.length && rule.methods.length === 1 && rule.methods[0] === 'GET';
}
function operatorRuleCredentialValid(rule, credential) {
  if (isAwsCredential(credential)) return false;
  try {
    if (!Object.hasOwn(operatorCredentialInputModes, rule.credential_input) ||
        rule.credential_input === 'insert' && Object.hasOwn(rule, 'placeholder')) return false;
    // Replacement has a stricter target contract than legacy insertion. Do not
    // apply its reserved-header/alias restrictions to an existing insert rule.
    const bearer = ['bearer', 'google_oauth', 'x_oauth'].includes(credential?.auth_type);
    if (bearer ? credential.header_name !== 'Authorization' : credential?.auth_type !== 'header' ||
        typeof credential.header_name !== 'string' || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(credential.header_name)) return false;
    clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential}); return true;
  } catch (_) { return false; }
}
function operatorRuleSupported(rule, catalog) {
  const credential = catalog?.credentials.find(item => item.id === rule?.credential_id && item.status === 'active');
  const application = catalog?.applications.find(item => item.id === rule?.application_id && item.status === 'active');
  if (isXPostRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    xPostRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && xPostAvailable(catalog, credential));
  if (isNpmInstallRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    npmInstallRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && npmInstallAvailable(catalog, credential));
  if (isAlchemyRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    alchemyRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && alchemyAvailable(catalog, credential, rule.chain));
  if (isXRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    xRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && xAvailable(catalog, credential));
  if (isNpmPublishRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    npmPublishRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && npmPublishAvailable(catalog, credential));
  if (isNpmRule(rule)) return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    npmRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && npmAvailable(catalog, credential));
  if (rule?.operation_bundle && typeof isGithubRule === 'function' && isGithubRule(rule))
    return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
      githubRuleValid(rule, credential) && operatorRuleCredentialValid(rule, credential) && githubAvailable(catalog, credential));
  return Boolean(credential && application && applicationProxyAuthenticationSupported(catalog, application) &&
    operatorRuleContentValid(rule, credential) && operatorRuleCredentialValid(rule, credential) &&
    (isGmailRule(rule) ? gmailAvailable(catalog, credential) : availableResponseModes(catalog).includes(rule.response_mode)) && availableCredentialInputModes(catalog).includes(rule.credential_input) &&
    (!Object.hasOwn(rule, 'request_body_mode') || availableRequestBodyChoices(catalog, credential).includes(rule.request_body_mode)));
}
function chooseModeOptions(id, items, placeholder) {
  const select = element(id); const previous = select.value;
  chooseOptions(id, items, placeholder);
  if (previous && !items.some(item => item.id === previous)) {
    const missing = textNode('option', 'Previous choice unavailable — choose again');
    missing.value = previous; missing.disabled = true; select.append(missing); select.value = previous;
  }
}
const operatorViews = {connect: 'Connect an app', overview: 'Overview', credentials: 'Accounts & keys', applications: 'Applications',
  'access-rules': 'Permissions', proxy: 'Proxy setup', audit: 'Audit log', notifications: 'Notifications'};
function operatorSyntheticPermissions(catalog) {
  // Destination matching is not provenance: preserve names/records and require
  // an explicit choice even if only one saved permission matches the fixture.
  return catalog?.access_rules.filter(rule => rule.upstream_url === 'https://demo-upstream:8443/echo' &&
    !Object.hasOwn(rule, 'operation_bundle') && rule.methods.length > 0 &&
    rule.methods.every(method => ['GET', 'POST'].includes(method))) || [];
}
const element = id => document.getElementById(id);
function textNode(tag, text, className) {
  const result = document.createElement(tag);
  if (text !== undefined) result.textContent = String(text);
  if (className) result.className = className;
  return result;
}
function operatorError(message) { const error = new Error('Operator request failed'); error.uiMessage = message; return error; }
function operatorMessage(error) { return error.uiMessage || 'The response was lost or unavailable. Review saved state before another attempt.'; }
function fieldLines(id) { return [...new Set(element(id).value.split(/\r?\n/).map(value => value.trim()).filter(Boolean))]; }
function chooseOptions(id, items, placeholder) {
  const select = element(id); const previous = select.value;
  const options = items.map(item => { const option = textNode('option', item.name); option.value = item.id; return option; });
  if (!options.length) { const option = textNode('option', placeholder); option.value = ''; options.push(option); }
  select.replaceChildren(...options);
  if (items.some(item => item.id === previous)) select.value = previous;
}
function resourceCard(item, badge, values) {
  const card = textNode('article', undefined, 'card'); card.dataset.resourceId = item.id;
  const heading = textNode('div', undefined, 'connection-head');
  heading.append(textNode('h3', item.name), textNode('span', badge, 'badge' + (badge === 'Active' ? ' active' : '')));
  const list = textNode('dl', undefined, 'metadata');
  for (const [label, value] of values) list.append(textNode('dt', label), textNode('dd', value || 'None'));
  card.append(heading, list); return card;
}
function renderCards(id, cards, empty) { element(id).replaceChildren(...(cards.length ? cards : [textNode('p', empty, 'muted')])); }
function projectGoogleAccount(item) {
  const text = (value, maximum) => typeof value === 'string' && value.length > 0 && value.length <= maximum && !/[\u0000-\u001f\u007f]/.test(value);
  const scopes = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
  if (!['active', 'quarantined'].includes(item.status) || item.header_name !== 'Authorization' ||
      !text(item.provider_account, 256) || !text(item.provider_subject, 256) ||
      !text(item.oauth_client_id, 256) || !/^[A-Za-z0-9._-]+\.apps\.googleusercontent\.com$/.test(item.oauth_client_id) ||
      item.permission_preset !== 'gmail_readonly' || !Array.isArray(item.scopes) ||
      item.scopes.length !== scopes.length || item.scopes.some((scope, index) => scope !== scopes[index]) ||
      !Number.isSafeInteger(item.active_rule_count) || item.active_rule_count < 0)
    throw operatorError('Saved Google account metadata is incomplete. Changes are disabled.');
  const result = {provider_account: item.provider_account, provider_subject: item.provider_subject,
    oauth_client_id: item.oauth_client_id, permission_preset: item.permission_preset, scopes: [...item.scopes]};
  if (item.status === 'quarantined') {
    if (!text(item.quarantined_at, 64) || !Number.isFinite(Date.parse(item.quarantined_at)) ||
        item.quarantine_reason !== 'operator_google_cleanup_fence' || item.provider_revocation_status !== 'not_proven' ||
        item.active_rule_count !== 0)
      throw operatorError('Saved Google quarantine metadata is incomplete. Changes are disabled.');
    Object.assign(result, {quarantined_at: item.quarantined_at, quarantine_reason: item.quarantine_reason,
      provider_revocation_status: item.provider_revocation_status});
  }
  return result;
}
function projectObservedAccountActivity(value, credentials, applications, accessRules) {
  // Observational evidence is not authority. Missing or malformed evidence makes
  // activity unavailable, without changing otherwise valid catalog permissions.
  const object = item => item !== null && typeof item === 'object' && !Array.isArray(item);
  const integer = (item, maximum) => Number.isSafeInteger(item) && item >= 0 && item <= maximum;
  const uuid = item => typeof item === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item);
  if (!object(value) || value.schema !== 'serverware.operatorAccountActivity/v1' ||
      !['available', 'unavailable'].includes(value.status) || value.chain_verification !== 'not_checked' ||
      !integer(value.observed_at_epoch_ms, 8640000000000000) || !object(value.window) ||
      !Array.isArray(value.accounts) || value.accounts.length > 1024) return null;
  const window = value.window;
  if (window.row_limit !== 256 || window.event_byte_limit !== 16384 || window.byte_limit !== 2097152 ||
      !integer(window.rows_scanned, window.row_limit) || !integer(window.bytes_read, window.byte_limit) ||
      !['has_older_rows', 'byte_budget_exhausted', 'incomplete'].every(key => typeof window[key] === 'boolean') ||
      !['oversized_events', 'invalid_events', 'unmatched_responses'].every(key => integer(window[key], window.rows_scanned)) ||
      (window.has_older_rows || window.byte_budget_exhausted || window.oversized_events || window.invalid_events || window.unmatched_responses) && !window.incomplete)
    return null;
  const result = {schema: value.schema, status: value.status, observed_at_epoch_ms: value.observed_at_epoch_ms,
    chain_verification: 'not_checked', window: Object.fromEntries(['row_limit', 'event_byte_limit', 'byte_limit',
      'rows_scanned', 'bytes_read', 'has_older_rows', 'byte_budget_exhausted', 'oversized_events', 'invalid_events',
      'unmatched_responses', 'incomplete'].map(key => [key, window[key]])), accounts: []};
  if (value.status === 'unavailable') return value.accounts.length === 0 && window.incomplete ? result : null;
  if (value.accounts.length !== credentials.length) return null;
  function observation(item, credentialId, response = false) {
    if (item === null) return null;
    if (!object(item) || !(uuid(item.event_id) || typeof item.event_id === 'string' && /^sha256:[0-9a-f]{64}$/.test(item.event_id)) ||
        !integer(item.recorded_at_epoch_ms, value.observed_at_epoch_ms) ||
        !Number.isSafeInteger(item.credential_version) || item.credential_version < 1 || window.rows_scanned === 0) return undefined;
    const event = {event_id: item.event_id, recorded_at_epoch_ms: item.recorded_at_epoch_ms, credential_version: item.credential_version};
    if (response) {
      const rule = accessRules.find(rule => rule.id === item.rule_id && rule.credential_id === credentialId && rule.application_id === item.application_id);
      if (!uuid(item.rule_id) || !uuid(item.application_id) || !rule || !applications.some(app => app.id === item.application_id)) return undefined;
      Object.assign(event, {application_id: item.application_id, rule_id: item.rule_id});
    }
    return event;
  }
  const seen = new Set();
  for (const item of value.accounts) {
    if (!object(item) || !uuid(item.credential_id) || seen.has(item.credential_id)) return null;
    const credential = credentials.find(record => record.id === item.credential_id);
    if (!credential || !['success', 'failure', 'unobserved'].includes(item.last_refresh_outcome)) return null;
    const response = observation(item.last_successful_response, item.credential_id, true);
    const success = observation(item.last_refresh_success, item.credential_id);
    const failure = observation(item.last_refresh_failure, item.credential_id);
    if ([response, success, failure].includes(undefined) ||
        !['google_oauth', 'x_oauth'].includes(credential.auth_type) && (success || failure || item.last_refresh_outcome !== 'unobserved') ||
        credential.auth_type === 'x_oauth' && (failure || item.last_refresh_outcome === 'failure') ||
        item.last_refresh_outcome === 'unobserved' && (success || failure) ||
        item.last_refresh_outcome === 'success' && (!success || failure && success.recorded_at_epoch_ms < failure.recorded_at_epoch_ms) ||
        item.last_refresh_outcome === 'failure' && (!failure || success && failure.recorded_at_epoch_ms < success.recorded_at_epoch_ms)) return null;
    seen.add(item.credential_id);
    result.accounts.push({credential_id: item.credential_id, last_successful_response: response,
      last_refresh_success: success, last_refresh_failure: failure, last_refresh_outcome: item.last_refresh_outcome});
  }
  return result;
}
function projectStaticKeyReplacementCapability(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'credential_types,path,schema' ||
      value.schema !== 'serverware.operatorStaticKeyReplacement/v1' ||
      value.path !== '/api/operator-demo/credentials/replace-key' ||
      !Array.isArray(value.credential_types) || value.credential_types.length !== 2 ||
      value.credential_types[0] !== 'bearer' || value.credential_types[1] !== 'header') return null;
  return {schema: value.schema, path: value.path, credential_types: ['bearer', 'header']};
}
function projectStaticKeyMetadata(item) {
  if (isGithubAppCredential(item)) return {}; // App private-key generations use their separate replacement contract.
  if (!['bearer', 'header'].includes(item.auth_type) || !Object.hasOwn(item, 'credential_generation')) return {};
  const generation = item.credential_generation;
  const valid = item.status === 'active' ? Number.isSafeInteger(generation) && generation > 0 :
    item.status === 'revoked' && generation === null;
  const hasTime = Object.hasOwn(item, 'key_replaced_at'); const time = item.key_replaced_at;
  if (!valid || hasTime && (typeof time !== 'string' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(time) ||
      !Number.isFinite(Date.parse(time)) || new Date(time).toISOString().slice(0, 19) !== time.slice(0, 19))) return {};
  return {credential_generation: generation, ...(hasTime ? {key_replaced_at: time} : {})};
}
function staticKeyReplacementAvailable(catalog, credential) {
  const metadata = credential ? projectStaticKeyMetadata(credential) : {};
  return Boolean(projectStaticKeyReplacementCapability(catalog?.capabilities?.static_key_replacement) &&
    !isGithubAppCredential(credential) &&
    credential?.status === 'active' && ['bearer', 'header'].includes(credential.auth_type) &&
    Number.isSafeInteger(metadata.credential_generation) && metadata.credential_generation > 0 &&
    metadata.credential_generation < Number.MAX_SAFE_INTEGER);
}
function projectApplicationProxyAuthenticationCapability(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== 'modes,path,schema' ||
      value.schema !== 'serverware.operatorProxyAuthentication/v1' ||
      value.path !== '/api/operator-demo/applications/proxy-authentication' ||
      !Array.isArray(value.modes) || value.modes.length !== 2 || value.modes[0] !== 'bearer' ||
      value.modes[1] !== 'basic_and_bearer_v1') return null;
  return {schema: value.schema, path: value.path, modes: ['bearer', 'basic_and_bearer_v1']};
}
function projectGoogleReauthorizationCapability(value) {
  const expected = {schema: 'serverware.operatorGoogleReauthorizationCapability/v1',
    path: '/api/operator-demo/oauth/google/reauthorize', status_path_prefix: '/api/operator-demo/oauth/google/reauthorize/',
    review_path_suffix: '/review', preserves_assignments: true, existing_account_only: true};
  return operatorExact(value, expected) ? {...expected} : null;
}
function applicationProxyAuthentication(application) {
  if (!application) return null;
  if (!Object.hasOwn(application, 'proxy_authentication')) return 'bearer';
  return ['bearer', 'basic_and_bearer_v1'].includes(application.proxy_authentication) ? application.proxy_authentication : null;
}
function applicationProxyAuthenticationSupported(catalog, application) {
  const mode = applicationProxyAuthentication(application);
  return mode === 'bearer' || mode === 'basic_and_bearer_v1' &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(application.id) &&
    Boolean(projectApplicationProxyAuthenticationCapability(catalog?.capabilities?.application_proxy_authentication));
}
function newApplicationProxyAuthentication(catalog) {
  return projectApplicationProxyAuthenticationCapability(catalog?.capabilities?.application_proxy_authentication) ?
    {proxy_authentication: 'basic_and_bearer_v1'} : {};
}
function projectCatalog(value) {
  if (value?.schema !== 'serverware.operatorCatalog/v1' || value.mode !== 'operator-development' ||
      value.productionReady !== false || value.hardwareVerified !== false || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !value.policy || !/^sha256:[a-f0-9]{64}$/.test(value.policy.policy_hash || '') ||
      !['active', 'pending'].includes(value.policy.activation) ||
      !['credentials', 'applications', 'access_rules', 'allowed_upstreams'].every(key => Array.isArray(value[key])))
    throw operatorError('This page did not receive the expected workspace catalog. Changes are disabled.');
  const pick = (item, names) => Object.fromEntries(names.map(name => [name, item[name]]));
  const base = ['id', 'name', 'status', 'created_at', 'revoked_at'];
  const project = (items, names, credentialRecords = false) => items.map(item => {
    if (!item || typeof item.id !== 'string' || typeof item.name !== 'string' ||
        !(['active', 'revoked'].includes(item.status) || credentialRecords && ['google_oauth', 'x_oauth'].includes(item.auth_type) && item.status === 'quarantined'))
      throw operatorError('Saved resource metadata is incomplete. Refresh before making changes.');
    return {...pick(item, [...base, ...names]), ...(credentialRecords ?
      isAwsCredential(item) ? projectAwsCredential(item) :
      item.auth_type === 'x_oauth' ? projectXAccount(item) :
      item.auth_type === 'google_oauth' ? projectGoogleAccount(item) : projectStaticKeyMetadata(item) : {})};
  });
  const credentials = project(value.credentials, ['auth_type', 'header_name', 'active_rule_count', 'legacy_upstream_origin'], true);
  credentials.forEach((credential, index) => {
    const original = value.credentials[index];
    if (isAwsCredential(original)) return; // Exact non-header tuple projection already validated above.
    if (original.auth_type === 'x_oauth') return; // Closed account projection is separate from static keys.
    if (Object.hasOwn(original, 'github_app') && !isGithubAppCredential(original))
      throw operatorError('Saved GitHub App marker and binding disagree. Changes are disabled.');
    if (!Object.hasOwn(original, 'connection_type')) return;
    const provider = isGithubCredential(original) ? 'github' : original.connection_type === 'npm_token_v1' ? 'npm' :
      original.connection_type === 'x_app_bearer_v1' ? 'x' : original.connection_type === 'alchemy_key_v1' ? 'alchemy' : null;
    if (provider === null || original.provider_id !== provider ||
        original.auth_type !== 'bearer' || original.header_name !== 'Authorization')
      throw operatorError('Saved provider connection metadata is unsupported. Changes are disabled.');
    credential.connection_type = original.connection_type; credential.provider_id = provider;
    if (isGithubAppCredential(original)) Object.assign(credential, projectGithubAppMetadata(original), projectGithubAppKeyMetadata(original));
  });
  const applications = project(value.applications, ['principal_id', 'token_expires_at_epoch_ms', 'token_generation', 'token_status', 'access_status', 'active_rule_count']);
  applications.forEach((application, index) => {
    if (Object.hasOwn(value.applications[index], 'proxy_authentication'))
      application.proxy_authentication = applicationProxyAuthentication(value.applications[index]);
  });
  const accessRules = project(value.access_rules, ['application_id', 'credential_id', 'route_id', 'upstream_url', 'methods',
    'request_fields', 'response_fields', 'query_keys', 'allowed_headers', 'response_mode', 'credential_input', 'enforcement']);
  accessRules.forEach((rule, index) => {
    for (const name of ['request_body_mode', 'placeholder', 'operation_bundle', 'age_policy', 'query_mode', 'repository', 'packages', 'package', 'tag', 'publishing_window', 'username', 'chain', 'quota', 'daily_quota'])
      if (Object.hasOwn(value.access_rules[index], name)) rule[name] = value.access_rules[index][name];
  });
  for (const rule of accessRules) if (rule.credential_input === undefined) rule.credential_input = 'insert';
  for (const rule of accessRules) for (const name of ['methods', 'request_fields', 'response_fields', 'query_keys', 'allowed_headers']) {
    if (!Array.isArray(rule[name]) || rule[name].some(item => typeof item !== 'string')) throw operatorError('Saved rule metadata is incomplete.');
  }
  for (const rule of accessRules) {
    const credential = credentials.find(item => item.id === rule.credential_id);
    const application = applications.find(item => item.id === rule.application_id);
    if (!credential || !application || !operatorRuleContentValid(rule, credential) || !operatorRuleCredentialValid(rule, credential) ||
        rule.status === 'active' && (credential.status !== 'active' || application.status !== 'active'))
      throw operatorError('Saved rule content modes or resource references are inconsistent. Changes are disabled.');
  }
  const npmApplications = accessRules.filter(rule => rule.status === 'active' && (isNpmRule(rule) || isNpmPublishRule(rule) || isNpmInstallRule(rule))).map(rule => rule.application_id);
  if (new Set(npmApplications).size !== npmApplications.length)
    throw operatorError('More than one active npm permission belongs to an application. Changes are disabled.');
  for (const rule of accessRules.filter(item => item.status === 'active' && isNpmInstallRule(item)))
    if (!npmInstallNewRuleAvailable({access_rules: accessRules.filter(item => item !== rule)}, rule.application_id))
      throw operatorError('npm installation conflicts with another registry permission. Changes are disabled.');
  const quarantinedAccounts = new Set(credentials.filter(item => item.status === 'quarantined').map(item => item.id));
  if (accessRules.some(rule => rule.status === 'active' && quarantinedAccounts.has(rule.credential_id)))
    throw operatorError('Saved Google account and access-rule states disagree. Changes are disabled.');
  const capabilities = pick(value.capabilities || {}, ['credential_types', 'response_modes', 'request_body_modes',
    'credential_input_modes', 'token_lifetime_seconds', 'oauth']);
  capabilities.static_key_replacement = projectStaticKeyReplacementCapability(value.capabilities?.static_key_replacement);
  capabilities.application_proxy_authentication = projectApplicationProxyAuthenticationCapability(value.capabilities?.application_proxy_authentication);
  capabilities.github = value.capabilities?.github == null ? null : projectGithubCapability(value.capabilities.github);
  capabilities.github_app = value.capabilities?.github_app == null ? null : projectGithubAppCapability(value.capabilities.github_app);
  capabilities.github_app_key_replacement = projectGithubAppKeyReplacementCapability(value.capabilities?.github_app_key_replacement);
  capabilities.npm = value.capabilities?.npm == null ? null : projectNpmCapability(value.capabilities.npm);
  capabilities.npm_publish = value.capabilities?.npm_publish == null ? null : projectNpmPublishCapability(value.capabilities.npm_publish);
  capabilities.npm_install = value.capabilities?.npm_install == null ? null : projectNpmInstallCapability(value.capabilities.npm_install);
  capabilities.x = value.capabilities?.x == null ? null : projectXCapability(value.capabilities.x);
  capabilities.x_post = value.capabilities?.x_post == null ? null : projectXPostCapability(value.capabilities.x_post);
  capabilities.x_oauth = value.capabilities?.x_oauth == null ? null : projectXAccountCapability(value.capabilities.x_oauth);
  capabilities.alchemy = value.capabilities?.alchemy == null ? null : projectAlchemyCapability(value.capabilities.alchemy);
  capabilities.aws_credentials = value.capabilities?.aws_credentials == null ? null : projectAwsCapability(value.capabilities.aws_credentials);
  if (capabilities.oauth !== true && (value.capabilities?.google_oauth != null || capabilities.oauth !== undefined && capabilities.oauth !== false))
    throw operatorError('Google capability metadata is inconsistent. Refresh before making changes.');
  capabilities.google_oauth = capabilities.oauth === true ? projectGoogleCapability(value.capabilities, location.origin) : null;
  capabilities.google_reauthorization = capabilities.google_oauth ?
    projectGoogleReauthorizationCapability(value.capabilities?.google_reauthorization) : null;
  capabilities.operation_bundles = projectOperationBundles(value.capabilities?.operation_bundles, capabilities.google_oauth);
  if (capabilities.google_oauth && !value.allowed_upstreams.includes('https://gmail.googleapis.com'))
    throw operatorError('Google destination capability is inconsistent. Changes are disabled.');
  return {schema: value.schema, revision: value.revision, policy: pick(value.policy, ['policy_hash', 'loaded_policy_hash', 'sequence', 'activation']),
    proxy_url: value.proxy_url, allowed_upstreams: value.allowed_upstreams.filter(item => typeof item === 'string'),
    credentials, applications, access_rules: accessRules, limits: value.limits, capabilities,
    observed_activity: projectObservedAccountActivity(value.observed_activity, credentials, applications, accessRules)};
}
function createOperatorWorkspace() {
  let writeInFlight = false;
  const consentOwners = new Set();
  const state = {catalog: null, consentHold: false, uncertain: false,
    get busy() { return writeInFlight || this.consentHold; }, set busy(value) { writeInFlight = value; }};
  const listeners = []; let epoch = 0; let poll; let polls = 0;
  const emit = () => {
    listeners.forEach(callback => callback());
    if (!state.catalog) for (const id of ['credentials-list', 'applications-list', 'access-rules-list']) {
      const list = element(id);
      for (const control of list.querySelectorAll('[data-action], select')) control.disabled = true;
      for (const badge of list.querySelectorAll('.badge')) { badge.textContent = 'Status unavailable'; badge.className = 'badge'; }
    }
  };
  function ready(collection) {
    if (!state.catalog || state.busy || state.uncertain) return false;
    const limit = state.catalog.limits?.[collection];
    return !limit || limit.active < limit.active_max && limit.retained < limit.retained_max;
  }
  function loaded() { const policy = state.catalog?.policy; return Boolean(policy && policy.activation === 'active' && policy.loaded_policy_hash === policy.policy_hash); }
  async function api(path, options = {}) {
    const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', redirect: 'error',
      signal: AbortSignal.timeout(30000), ...options});
    if ([401, 403].includes(response.status)) {
      state.catalog = null; emit(); throw operatorError('Your session or request origin could not be verified. Reload and sign in again.');
    }
    if (!response.ok) {
      const messages = {404: 'The resource was not found. Review refreshed saved state.',
        409: 'Saved state changed, the resource is in use, or capacity was reached. Review refreshed state before trying again.',
        413: 'The request was too large.', 422: 'Check the form fields. The service rejected this configuration.',
        503: 'The service could not confirm the result. Do not assume the change failed.'};
      throw operatorError(messages[response.status] || 'The service rejected the request. Refresh before trying again.');
    }
    if (!response.headers.get('content-type')?.includes('application/json')) throw operatorError('The service did not return JSON. Reload and sign in again.');
    return response.json();
  }
  async function refresh({manual = false} = {}) {
    if (manual) polls = 0;
    clearTimeout(poll); const version = ++epoch;
    try {
      const next = projectCatalog(await api('/api/operator-demo/catalog'));
      if (version !== epoch) return false;
      state.catalog = next; element('load-error').hidden = true;
      element('mutation-review-confirm').disabled = !state.uncertain;
      emit();
      if (!loaded() && polls++ < 15) poll = setTimeout(() => refresh(), 2000);
      return true;
    } catch (error) {
      if (version !== epoch) return false;
      state.catalog = null; element('load-error-text').textContent = operatorMessage(error); element('load-error').hidden = false;
      element('mutation-review-confirm').disabled = true; emit(); return false;
    }
  }
  function requireReview(message) {
    state.uncertain = true; element('mutation-review').hidden = false;
    element('mutation-review-text').textContent = message + ' No automatic retry was sent. Review the resource lists below before allowing another change. A lost one-time token cannot be recovered; replacing it requires explicit rotation.';
    element('mutation-review-confirm').disabled = true;
    emit();
  }
  async function mutate(path, body, statusId, onSuccess = () => {}) {
    if (!state.catalog || state.busy || state.uncertain) return false;
    const reviewed = {expected_revision: state.catalog.revision, expected_policy_hash: state.catalog.policy.policy_hash};
    state.busy = true; ++epoch; clearTimeout(poll); emit(); element(statusId).textContent = 'Saving...';
    let success = false;
    try {
      const pending = api('/api/operator-demo/' + path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...body, ...reviewed})});
      for (const name of ['secret', 'private_key_pem', 'access_key_id', 'secret_access_key', 'session_token'])
        if (Object.hasOwn(body, name)) body[name] = '';
      const result = await pending; await onSuccess(result); success = true;
      element(statusId).textContent = 'Saved. Refreshing the current state and proxy enforcement...';
    } catch (error) {
      requireReview(operatorMessage(error));
      element(statusId).textContent = operatorMessage(error);
    } finally { for (const name of ['secret', 'private_key_pem', 'access_key_id', 'secret_access_key', 'session_token'])
      if (Object.hasOwn(body, name)) body[name] = ''; }
    await refresh(); state.busy = false; emit(); return success;
  }
  element('mutation-review-confirm').addEventListener('click', () => {
    if (!state.catalog || state.busy) return;
    state.uncertain = false; element('mutation-review').hidden = true; emit();
  });
  window.addEventListener('pagehide', () => clearTimeout(poll));
  return {state, api, refresh, mutate, requireReview, ready, loaded, emit, writeInFlight: () => writeInFlight,
    setConsentHold(value, owner = 'google-consent') {
      if (value) consentOwners.add(owner); else consentOwners.delete(owner);
      const held = consentOwners.size > 0;
      if (state.consentHold !== held) { state.consentHold = held; emit(); }
    },
    subscribe: callback => listeners.push(callback)};
}

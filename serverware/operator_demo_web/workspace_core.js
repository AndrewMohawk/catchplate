// Public catalog state and transport only. Provider secrets and client tokens do
// not belong in this state. All resource views share one explicit mutation gate.
const operatorMethods = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
const operatorResponseModes = Object.freeze({unfiltered_json: 'Do not filter response content (JSON)',
  projected_json: 'Only return selected JSON fields'});
function availableResponseModes(catalog) {
  const advertised = catalog?.capabilities?.response_modes;
  return Array.isArray(advertised) ? Object.keys(operatorResponseModes).filter(mode => advertised.includes(mode)) : [];
}
const operatorCredentialInputModes = Object.freeze({insert: 'Add credential automatically', replace_exact: 'Replace a dummy header value'});
function availableCredentialInputModes(catalog) {
  const advertised = catalog?.capabilities?.credential_input_modes;
  return Array.isArray(advertised) ? Object.keys(operatorCredentialInputModes).filter(mode => advertised.includes(mode)) : [];
}
const operatorViews = {connect: 'Connect an app', overview: 'Overview', credentials: 'Credentials', applications: 'Applications',
  'access-rules': 'Access rules', proxy: 'Proxy setup', audit: 'Audit log'};
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
function projectCatalog(value) {
  if (value?.schema !== 'serverware.operatorCatalog/v1' || value.mode !== 'operator-development' ||
      value.productionReady !== false || value.hardwareVerified !== false || !Number.isSafeInteger(value.revision) || value.revision < 1 ||
      !value.policy || !/^sha256:[a-f0-9]{64}$/.test(value.policy.policy_hash || '') ||
      !['active', 'pending'].includes(value.policy.activation) ||
      !['credentials', 'applications', 'access_rules', 'allowed_upstreams'].every(key => Array.isArray(value[key])))
    throw operatorError('This page did not receive the expected workspace catalog. Changes are disabled.');
  const pick = (item, names) => Object.fromEntries(names.map(name => [name, item[name]]));
  const base = ['id', 'name', 'status', 'created_at', 'revoked_at'];
  const project = (items, names) => items.map(item => {
    if (!item || typeof item.id !== 'string' || typeof item.name !== 'string' || !['active', 'revoked'].includes(item.status))
      throw operatorError('Saved resource metadata is incomplete. Refresh before making changes.');
    return pick(item, [...base, ...names]);
  });
  const credentials = project(value.credentials, ['auth_type', 'header_name', 'active_rule_count', 'legacy_upstream_origin']);
  const applications = project(value.applications, ['principal_id', 'token_expires_at_epoch_ms', 'token_generation', 'token_status', 'access_status', 'active_rule_count']);
  const accessRules = project(value.access_rules, ['application_id', 'credential_id', 'route_id', 'upstream_url', 'methods',
    'request_fields', 'response_fields', 'query_keys', 'allowed_headers', 'response_mode', 'credential_input', 'placeholder', 'enforcement']);
  for (const rule of accessRules) if (rule.credential_input === undefined) rule.credential_input = 'insert';
  for (const rule of accessRules) for (const name of ['methods', 'request_fields', 'response_fields', 'query_keys', 'allowed_headers']) {
    if (!Array.isArray(rule[name]) || rule[name].some(item => typeof item !== 'string')) throw operatorError('Saved rule metadata is incomplete.');
  }
  return {schema: value.schema, revision: value.revision, policy: pick(value.policy, ['policy_hash', 'loaded_policy_hash', 'sequence', 'activation']),
    proxy_url: value.proxy_url, allowed_upstreams: value.allowed_upstreams.filter(item => typeof item === 'string'),
    credentials, applications, access_rules: accessRules, limits: value.limits, capabilities: value.capabilities};
}
function createOperatorWorkspace() {
  const state = {catalog: null, busy: false, uncertain: false};
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
  async function mutate(path, body, statusId, onSuccess = () => {}) {
    if (!state.catalog || state.busy || state.uncertain) return false;
    const reviewed = {expected_revision: state.catalog.revision, expected_policy_hash: state.catalog.policy.policy_hash};
    state.busy = true; ++epoch; clearTimeout(poll); emit(); element(statusId).textContent = 'Saving...';
    let success = false;
    try {
      const pending = api('/api/operator-demo/' + path, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...body, ...reviewed})});
      if (Object.hasOwn(body, 'secret')) body.secret = '';
      const result = await pending; await onSuccess(result); success = true;
      element(statusId).textContent = 'Saved. Refreshing the current state and proxy enforcement...';
    } catch (error) {
      state.uncertain = true; element('mutation-review').hidden = false;
      element('mutation-review-text').textContent = operatorMessage(error) + ' No automatic retry was sent. Review the resource lists below before allowing another change. A lost one-time token cannot be recovered; replacing it requires explicit rotation.';
      element(statusId).textContent = operatorMessage(error);
    } finally { if (Object.hasOwn(body, 'secret')) body.secret = ''; }
    await refresh(); state.busy = false; emit(); return success;
  }
  element('mutation-review-confirm').addEventListener('click', () => {
    if (!state.catalog || state.busy) return;
    state.uncertain = false; element('mutation-review').hidden = true; emit();
  });
  window.addEventListener('pagehide', () => clearTimeout(poll));
  return {state, api, refresh, mutate, ready, loaded, emit, subscribe: callback => listeners.push(callback)};
}

// AWS tuple custody only. No header injection, signing, grant or client recipe.
const operatorAwsNotice = 'Stored only — ECR publishing not available yet.';
function awsCapabilityDescriptor() {
  return {schema: 'serverware.operatorAwsCredentials/v1', connection_type: 'aws_sigv4_v1',
    create_path: '/api/operator-demo/credentials/aws-sigv4',
    replace_path: '/api/operator-demo/credentials/aws-sigv4/replace',
    revoke_path: '/api/operator-demo/credentials/revoke', credential_kinds: ['long_term', 'session'],
    signing_available: false, automatic_renewal: false};
}
function projectAwsCapability(value) {
  const expected = awsCapabilityDescriptor();
  return operatorExact(value, expected) ? expected : null;
}
function awsUtc(value) {
  return typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && Date.parse(value) >= 0 && new Date(value).toISOString() === value.slice(0, -1) + '.000Z';
}
function projectAwsCredential(item) {
  const allowed = ['id', 'name', 'status', 'created_at', 'revoked_at', 'ordinal', 'version', 'auth_type',
    'header_name', 'active_rule_count', 'legacy_upstream_origin', 'connection_type', 'provider_id',
    'credential_kind', 'expires_at', 'expired', 'signing_available', 'credential_generation', 'key_replaced_at'];
  const generation = item?.credential_generation;
  if (!item || Object.keys(item).some(key => !allowed.includes(key)) ||
      item.auth_type !== 'aws_sigv4_v1' || item.connection_type !== 'aws_sigv4_v1' ||
      item.provider_id !== 'aws' || item.header_name !== null || item.legacy_upstream_origin != null ||
      item.signing_available !== false || typeof item.expired !== 'boolean' || item.active_rule_count !== 0 ||
      !['long_term', 'session'].includes(item.credential_kind) ||
      (item.credential_kind === 'long_term' ? item.expires_at !== null || item.expired : !awsUtc(item.expires_at)) ||
      (item.status === 'active' ? !Number.isSafeInteger(generation) || generation < 1 : item.status !== 'revoked' || generation !== null) ||
      typeof item.id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(item.id) ||
      typeof item.name !== 'string' || !item.name.length || item.name.length > 128 ||
      typeof item.created_at !== 'string' || !Number.isFinite(Date.parse(item.created_at)) ||
      Object.hasOwn(item, 'key_replaced_at') && (typeof item.key_replaced_at !== 'string' ||
        !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$/.test(item.key_replaced_at) ||
        !Number.isFinite(Date.parse(item.key_replaced_at)) || new Date(item.key_replaced_at).toISOString().slice(0, 19) !== item.key_replaced_at.slice(0, 19)))
    throw operatorError('Saved AWS credential metadata is unsupported. Changes are disabled.');
  return {connection_type: 'aws_sigv4_v1', provider_id: 'aws', credential_kind: item.credential_kind,
    expires_at: item.expires_at, expired: item.expired, signing_available: false, credential_generation: generation,
    ...(Object.hasOwn(item, 'key_replaced_at') ? {key_replaced_at: item.key_replaced_at} : {})};
}
function awsCredentialIdentity(item) {
  projectAwsCredential(item);
  return Object.fromEntries(['id', 'name', 'status', 'created_at', 'revoked_at', 'auth_type', 'header_name',
    'active_rule_count', 'connection_type', 'provider_id', 'credential_kind', 'expires_at',
    'signing_available', 'credential_generation', 'key_replaced_at'].map(key => [key, item[key]]));
}
function awsStorageAvailable(catalog) { return Boolean(projectAwsCapability(catalog?.capabilities?.aws_credentials)); }
function awsReplaceAvailable(catalog, credential) {
  return awsStorageAvailable(catalog) && isAwsCredential(credential) && credential.status === 'active' &&
    Number.isSafeInteger(credential.credential_generation) && credential.credential_generation < Number.MAX_SAFE_INTEGER;
}
function awsCredentialRows(credential) {
  const expired = credential.expired || credential.credential_kind === 'session' && Date.parse(credential.expires_at) <= Date.now();
  return [['Authentication', 'AWS Signature Version 4 credentials — storage only'],
    ['Credential kind', credential.credential_kind === 'session' ? 'Temporary session' : 'Long-term access key'],
    ['Session expiry (UTC)', credential.expires_at || 'No session expiry supplied'],
    ['Expiry observation', credential.credential_kind === 'long_term' ? 'No session expiry; validity not tested' :
      expired ? 'Expired — replace the complete tuple explicitly' : 'Not past supplied expiry; validity not tested'],
    ['Availability', operatorAwsNotice], ['Automatic renewal', 'None']];
}
function createAwsCredentialsView(workspace) {
  const selector = element('credential-storage-type');
  const form = element('aws-credential-form'); const panel = element('aws-replace-panel');
  let draft = null;
  const writable = () => Boolean(workspace.state.catalog && !workspace.state.busy && !workspace.state.uncertain);
  const status = (id, text) => { element(id).textContent = text; };
  const clear = prefix => { for (const field of ['access-key-id', 'secret-access-key', 'session-token']) element(prefix + '-' + field).value = ''; };
  const clearBody = body => { if (body) for (const field of ['access_key_id', 'secret_access_key', 'session_token']) body[field] = ''; };
  function configure(prefix) {
    const session = element(prefix + '-kind').value === 'session';
    element(prefix + '-session-fields').hidden = !session;
    for (const field of ['session-token', 'expires-at']) {
      const control = element(prefix + '-' + field); control.disabled = !session; control.required = session;
    }
  }
  function close() { clear('aws-replace'); draft = null; panel.hidden = true; element('aws-replace-fields').disabled = true; }
  function reviewed(id) {
    const catalog = workspace.state.catalog;
    const credential = catalog?.credentials.find(item => item.id === id);
    if (!awsReplaceAvailable(catalog, credential)) return null;
    return {id, identity: awsCredentialIdentity(credential), revision: catalog.revision,
      policy: catalog.policy.policy_hash, sequence: catalog.policy.sequence,
      bindings: keyReplacementBindings(catalog), capability: projectAwsCapability(catalog.capabilities.aws_credentials)};
  }
  function render() {
    const available = awsStorageAvailable(workspace.state.catalog);
    selector.disabled = !writable(); element('credential-storage-aws-option').disabled = !available;
    form.hidden = selector.value !== 'aws'; element('credential-form').hidden = selector.value === 'aws';
    element('aws-storage-availability').hidden = selector.value !== 'aws';
    element('credential-fields').disabled = selector.value !== 'manual' || !workspace.ready('credentials');
    element('aws-credential-fields').disabled = !available || !workspace.ready('credentials');
    element('aws-storage-availability').textContent = available ? operatorAwsNotice +
      ' Save or replace credentials only. No AWS validation request, application access or automatic renewal.' :
      'AWS credential storage is not advertised by this deployment. Manual header credentials are not a substitute.';
    if (!available || workspace.state.uncertain || !workspace.state.catalog) { clear('aws-credential'); close(); }
    if (draft && (!writable() || !operatorExact(reviewed(draft.id), draft))) {
      close(); status('aws-replace-status', 'Saved state changed. The new tuple was cleared; review and reopen replacement. No request was retried.');
    }
    element('aws-replace-fields').disabled = !draft || !writable();
    configure('aws-credential'); configure('aws-replace');
  }
  function tuple(prefix) {
    const result = {credential_kind: element(prefix + '-kind').value,
      access_key_id: element(prefix + '-access-key-id').value, secret_access_key: element(prefix + '-secret-access-key').value,
      session_token: element(prefix + '-kind').value === 'session' ? element(prefix + '-session-token').value : null,
      expires_at: element(prefix + '-kind').value === 'session' ? element(prefix + '-expires-at').value : null};
    clear(prefix); // Clear DOM before validation errors or the first await.
    const session = result.credential_kind === 'session';
    if (!['long_term', 'session'].includes(result.credential_kind) ||
        !(session ? /^ASIA[A-Z0-9]{16}$/ : /^AKIA[A-Z0-9]{16}$/).test(result.access_key_id) ||
        !/^[A-Za-z0-9/+=]{40}$/.test(result.secret_access_key) ||
        session && (!/^[!-~]{1,8192}$/.test(result.session_token) || !awsUtc(result.expires_at) || Date.parse(result.expires_at) <= Date.now())) {
      clearBody(result); throw operatorError('Enter the complete AWS tuple with the matching key kind and a future exact UTC expiry for a session. The server checks expiry again. Values were cleared; no request was sent.');
    }
    return result;
  }
  function receipt(result, before, expected, replacing) {
    const item = result?.credential;
    const identity = awsCredentialIdentity(item);
    if (result.revision !== before.revision + 1 || result.policy?.policy_hash !== before.policy ||
        result.policy.sequence !== before.sequence || item.status !== 'active' ||
        item.credential_kind !== expected.kind || item.expires_at !== expected.expiry || item.name !== expected.name ||
        item.credential_generation !== (replacing ? before.identity.credential_generation + 1 : 1) ||
        !replacing && before.ids.includes(item.id))
      throw operatorError('The AWS receipt could not be confirmed. Inspect saved state; do not repeat the action.');
    if (replacing) {
      const detail = result.key_replacement;
      if (!['id', 'name', 'created_at', 'auth_type', 'header_name', 'connection_type', 'provider_id', 'active_rule_count'].every(key => item[key] === before.identity[key]) ||
          !Object.hasOwn(item, 'key_replaced_at') || detail?.previous_credential_generation !== before.identity.credential_generation ||
          detail.credential_generation !== item.credential_generation || !['local_completed', 'local_unconfirmed'].includes(detail.cache_invalidation) ||
          detail.in_flight_requests !== 'not_recalled')
        throw operatorError('The AWS replacement receipt could not be confirmed. Inspect saved state; do not repeat the action.');
    }
    return identity;
  }
  async function submit(event, replacing) {
    event.preventDefault(); const prefix = replacing ? 'aws-replace' : 'aws-credential';
    const statusId = prefix + '-status'; let body = null; let attempted = false;
    try {
      if (!writable() || !awsStorageAvailable(workspace.state.catalog) ||
          (replacing ? !draft || !operatorExact(reviewed(draft.id), draft) : selector.value !== 'aws' || !workspace.ready('credentials'))) return;
      if (!event.currentTarget.reportValidity()) return;
      const catalog = workspace.state.catalog;
      const before = replacing ? draft : {revision: catalog.revision, policy: catalog.policy.policy_hash,
        sequence: catalog.policy.sequence, ids: catalog.credentials.map(item => item.id), bindings: keyReplacementBindings(catalog)};
      body = tuple(prefix);
      const expected = {name: replacing ? before.identity.name : element('aws-credential-name').value.trim(),
        kind: body.credential_kind, expiry: body.expires_at};
      if (replacing) { body.id = before.id; body.expected_credential_generation = before.identity.credential_generation; close(); }
      else body.name = expected.name;
      let confirmed;
      attempted = true;
      const pending = workspace.mutate(replacing ? 'credentials/aws-sigv4/replace' : 'credentials/aws-sigv4', body, statusId,
        result => { confirmed = receipt(result, before, expected, replacing); });
      clearBody(body); // mutate synchronously serialized the request, not its later receipt.
      const accepted = await pending;
      if (!accepted) return;
      const refreshed = workspace.state.catalog;
      const current = refreshed?.credentials.find(item => item.id === confirmed?.id);
      if (!current || refreshed.revision !== before.revision + 1 || refreshed.policy.policy_hash !== before.policy ||
          refreshed.policy.sequence !== before.sequence || keyReplacementBindings(refreshed) !== before.bindings ||
          !operatorExact(awsCredentialIdentity(current), confirmed)) {
        workspace.requireReview('The acknowledged AWS change could not be matched to refreshed saved state. Do not assume rollback.');
        status(statusId, 'AWS change acknowledged, but refreshed state is unconfirmed. Inspect it before another action.'); return;
      }
      status(statusId, (replacing ? 'Complete AWS tuple replaced in Serverware. ' : 'AWS credentials saved in Serverware. ') +
        operatorAwsNotice + ' No AWS request was made; this does not revoke or renew credentials at AWS.');
    } catch (error) {
      if (attempted) workspace.requireReview('The AWS change outcome could not be confirmed. Inspect saved state before another action.');
      status(statusId, operatorMessage(error));
    }
    finally { clear(prefix); clearBody(body); render(); }
  }
  function open(id) {
    close(); if (!writable()) return;
    draft = reviewed(id); if (!draft) return;
    selector.value = 'manual'; clear('aws-credential');
    element('aws-replace-title').textContent = 'Replace AWS credentials · ' + draft.identity.name;
    element('aws-replace-kind').value = draft.identity.credential_kind;
    element('aws-replace-expires-at').value = '';
    status('aws-replace-status', 'Enter a complete new tuple. The current access key ID and secrets are never returned.');
    panel.hidden = false; render(); element('aws-replace-access-key-id').focus();
  }
  selector.addEventListener('change', () => { clear('aws-credential'); close(); render(); });
  for (const prefix of ['aws-credential', 'aws-replace']) {
    element(prefix + '-kind').addEventListener('change', () => { clear(prefix); element(prefix + '-expires-at').value = ''; configure(prefix); });
    element(prefix + '-form').addEventListener('invalid', () => clear(prefix), true);
  }
  form.addEventListener('submit', event => submit(event, false));
  element('aws-replace-form').addEventListener('submit', event => submit(event, true));
  element('aws-replace-cancel').addEventListener('click', () => { close(); status('aws-replace-status', 'Replacement cancelled. No request was sent.'); });
  for (const event of ['hashchange', 'pagehide']) window.addEventListener(event, () => { clear('aws-credential'); close(); });
  workspace.subscribe(render);
  return {open, render};
}

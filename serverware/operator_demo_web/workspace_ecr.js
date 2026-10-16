// Typed ECR publication only. AWS tuples never become generic header credentials.
const operatorEcr = Object.freeze({bundle: 'aws_ecr_publish_v1', input: 'aws_ecr_signing_v1', response: 'aws_ecr_publication_json_v1',
  headers: ['amz-sdk-invocation-id', 'amz-sdk-request', 'authorization', 'user-agent', 'x-amz-date', 'x-amz-target']});
function ecrCapabilityDescriptor() {
  return {schema: 'serverware.operatorEcrPublication/v1', connection_type: 'aws_sigv4_v1',
    create_rule_path: '/api/operator-demo/access-rules/aws-ecr-publication', operation_bundles: [operatorEcr.bundle],
    approval_mode: 'host_review_v1', publication_approval_required: true, credential_input: operatorEcr.input,
    response_mode: operatorEcr.response, route_scope: 'one_per_client_region', max_request_bytes: 16777216, max_response_bytes: 26214400,
    automatic_retries: false, source_pair_required: true};
}
function projectEcrCapability(value) { return operatorExact(value, ecrCapabilityDescriptor()) ? ecrCapabilityDescriptor() : null; }
function isEcrRule(rule) { return rule?.operation_bundle === operatorEcr.bundle; }
function ecrScope(value) {
  const result = Object.fromEntries(['registry_id', 'region', 'repository_name', 'image_tag'].map(key => [key, value?.[key]]));
  if (!/^\d{12}$/.test(result.registry_id || '') || typeof result.registry_id !== 'string' ||
      typeof result.region !== 'string' || !/^[a-z]{2}-[a-z]+-[1-9][0-9]?$/.test(result.region) || result.region.startsWith('cn-') ||
      typeof result.repository_name !== 'string' || result.repository_name.length < 2 || result.repository_name.length > 256 ||
      !/^(?:[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*\/)*[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$/.test(result.repository_name) ||
      typeof result.image_tag !== 'string' || !/^[!-~]{1,300}$/.test(result.image_tag))
    throw operatorError('Enter one exact AWS account, supported region, existing repository and image tag. Wildcard permissions are not supported.');
  return result;
}
function ecrOrigin(region) { return 'https://api.ecr.' + ecrScope({registry_id: '123456789012', region, repository_name: 'scope-check', image_tag: 'check'}).region + '.amazonaws.com'; }
function ecrRuleFields(scope) {
  const value = ecrScope(scope);
  return {operation_bundle: operatorEcr.bundle, ...value, approval_mode: 'host_review_v1', publication_approval_required: true,
    upstream_url: ecrOrigin(value.region) + '/', methods: ['POST'], request_fields: [], response_fields: [], query_keys: [],
    allowed_headers: [...operatorEcr.headers], response_mode: operatorEcr.response, credential_input: operatorEcr.input};
}
function ecrRuleValid(rule, credential) {
  if (!isEcrRule(rule) || !isAwsCredential(credential) || rule.credential_input !== operatorEcr.input ||
      ['placeholder', 'request_body_mode', 'app_preset', 'scope', 'daily_post_attempt_limit'].some(key => Object.hasOwn(rule, key))) return false;
  try { const expected = ecrRuleFields(rule); return Object.entries(expected).every(([key, value]) => operatorExact(rule[key], value)); }
  catch (_) { return false; }
}
function ecrAvailable(catalog, credential, rule = null) {
  return Boolean(projectEcrCapability(catalog?.capabilities?.ecr_publication) && isAwsCredential(credential) &&
    credential.status === 'active' && !credential.expired &&
    (credential.credential_kind !== 'session' || Date.parse(credential.expires_at) > Date.now()) &&
    (!rule || catalog.allowed_upstreams.includes(ecrOrigin(rule.region))));
}
function ecrRulePayload(rule) {
  return Object.fromEntries(['name', 'application_id', 'credential_id', 'operation_bundle', 'registry_id', 'region',
    'repository_name', 'image_tag', 'approval_mode'].map(key => [key, rule[key]]));
}
function ecrRuleRestrictions(rule) {
  return [['Permission', 'Publish one reviewed image to an existing ECR repository'],
    ['AWS account / region', rule.registry_id + ' / ' + rule.region], ['Repository / tag', rule.repository_name + ':' + rule.image_tag],
    ['Image review', 'Mandatory approval of the staged manifest and every verified blob before client publication.'],
    ['Limits', 'One ECR permission per client and region. No repository creation, deletion, Docker login or Docker push. No automatic retries.']];
}
function renderEcrCompatibility(id) {
  element(id).replaceChildren(...[
    'The Python Boto3 example stages one OCI or Docker schema-2 image in Serverware, requests whole-image review, then publishes only after an explicit client command.',
    'Original manifest and every blob are hashed and bounded. This does not establish image safety, scan contents or execute the image. No multi-platform image index, Docker archive, Docker login or Docker push.',
    'Host-trusted approval binds the exact client, credential generation, policy, account, region, repository, tag and staged bytes. A server administrator can bypass this control.',
    'Approval alone sends nothing to AWS. An uncertain write is never automatically retried or resumed. Saved credentials and a loaded permission are not proof of AWS entitlement.'
  ].map(value => textNode('p', value, 'small muted')));
}
function ecrClientConfig(catalog, application, rule, token, caFile, proxyCaFile = null) {
  const proxy = new URL(catalog.proxy_url);
  if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
      !operatorRuleSupported(rule, catalog) || application.id !== rule.application_id || applicationProxyAuthentication(application) !== 'basic_and_bearer_v1' ||
      typeof token !== 'string' || !token || !/^sha256:[a-f0-9]{64}$/.test(catalog.policy.policy_hash))
    throw operatorError('A current ECR permission, HTTPS proxy and matching client login are required.');
  return {schema: 'serverware.awsEcrPublicationClient/v1', operation_bundle: operatorEcr.bundle,
    application_id: application.id, access_rule_id: rule.id, expected_policy_hash: catalog.policy.policy_hash, ...ecrScope(rule),
    proxy_url: proxy.origin, control_api_url: proxy.origin + '/v1/ecr/publications', proxy_authentication: 'basic_and_bearer_v1',
    proxy_username: application.id, proxy_password: token, token_expires_at_epoch_ms: application.token_expires_at_epoch_ms,
    ca_file: caFile || './serverware-ca.pem', proxy_ca_file: proxyCaFile || null};
}
function downloadEcrConfig(config) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2) + '\n'], {type: 'application/json'}));
  const anchor = textNode('a'); anchor.href = url; anchor.download = 'serverware-client.private.json'; document.body.append(anchor); anchor.click(); anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function renderEcrClient(workspace, application, rule, applications) {
  const catalog = workspace.state.catalog, credential = catalog.credentials.find(item => item.id === rule.credential_id);
  const supported = operatorRuleSupported(rule, catalog), valid = application.token_status === 'valid' && application.token_expires_at_epoch_ms > Date.now();
  const ready = supported && valid && workspace.loaded() && rule.enforcement === 'active' && application.access_status === 'active' && !workspace.state.busy && !workspace.state.uncertain;
  element('ecr-client-controls').hidden = false;
  element('client-template-title').textContent = 'AWS ECR · Stage, review, then publish';
  element('client-template-warning').textContent = 'Publish only the exact staged image you deliberately select. Approval does not publish. A server administrator can bypass host-trusted approval.';
  element('ecr-client-scope').textContent = rule.registry_id + ' / ' + rule.region + ' / ' + rule.repository_name + ':' + rule.image_tag;
  element('client-command').textContent = 'python publish.py stage --config ./serverware-client.private.json --stage /absolute/reviewed-stage';
  element('client-guidance').textContent = ready ? 'From examples/ecr-publish-python. First prepare a local stage using the linked instructions. Staging uploads bytes to Serverware, not AWS. Then open Pending actions for image review. Select that exact publication below to see status and the explicit publish command.' :
    !supported ? 'ECR publishing is unavailable until the matching owner, proxy and approved regional destination are ready. Refresh saved state; no AWS request was sent.' :
    'Wait for the saved policy to load and a valid client token before staging. No provider access has been tested.';
  element('copy-command').disabled = !ready;
  element('download-config').disabled = !ready || !applications.tokenFor(application.id);
  element('proxy-method').hidden = true; element('proxy-method').disabled = true;
  document.querySelector('label[for="proxy-method"]').hidden = true;
  renderEcrCompatibility('client-compatibility-content'); renderOperatorExampleProjects(rule, catalog);
  return ready;
}

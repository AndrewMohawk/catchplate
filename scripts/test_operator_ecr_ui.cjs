'use strict';
// Pure UI contracts and named synthetic metadata. No requests or provider calls.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {execFileSync} = require('node:child_process');
const {resolve} = require('node:path');
const vm = require('node:vm');
const ROOT = resolve(__dirname, '..'), NOW = Date.now();
const IDS = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222',
  '33333333-3333-4333-8333-333333333333', '44444444-4444-4444-8444-444444444444', '55555555-5555-4555-8555-555555555555'];
const hash = n => 'sha256:' + n.toString(16).padStart(64, '0');
const copy = value => JSON.parse(JSON.stringify(value));
const SCOPE = {registry_id: '123456789012', region: 'us-east-1', repository_name: 'team/service', image_tag: 'release-1'};
const HEADERS = ['amz-sdk-invocation-id', 'amz-sdk-request', 'authorization', 'user-agent', 'x-amz-date', 'x-amz-target'];
const CAPABILITY = {schema: 'serverware.operatorEcrPublication/v1', connection_type: 'aws_sigv4_v1',
  create_rule_path: '/api/operator-demo/access-rules/aws-ecr-publication', operation_bundles: ['aws_ecr_publish_v1'],
  approval_mode: 'host_review_v1', publication_approval_required: true, credential_input: 'aws_ecr_signing_v1',
  response_mode: 'aws_ecr_publication_json_v1', route_scope: 'one_per_client_region', max_request_bytes: 16777216, max_response_bytes: 26214400,
  automatic_retries: false, source_pair_required: true};
const credential = () => ({id: IDS[0], name: 'Release AWS credentials', status: 'active', created_at: new Date(NOW).toISOString(),
  auth_type: 'aws_sigv4_v1', connection_type: 'aws_sigv4_v1', provider_id: 'aws', header_name: null,
  credential_kind: 'long_term', expires_at: null, expired: false, signing_available: false, credential_generation: 1, active_rule_count: 1});
const application = () => ({id: IDS[1], name: 'Release CI', status: 'active', created_at: new Date(NOW).toISOString(),
  principal_id: 'agent:operator-demo:' + IDS[1], token_expires_at_epoch_ms: NOW + 86400000, token_generation: 1,
  token_status: 'valid', access_status: 'active', active_rule_count: 1, proxy_authentication: 'basic_and_bearer_v1'});
const rule = () => ({id: IDS[2], name: 'Publish release image', status: 'active', created_at: new Date(NOW).toISOString(),
  application_id: IDS[1], credential_id: IDS[0], route_id: 'operator.' + IDS[2], operation_bundle: 'aws_ecr_publish_v1', ...SCOPE,
  publication_approval_required: true, approval_mode: 'host_review_v1', upstream_url: 'https://api.ecr.us-east-1.amazonaws.com/',
  methods: ['POST'], request_fields: [], response_fields: [], query_keys: [], allowed_headers: HEADERS,
  response_mode: 'aws_ecr_publication_json_v1', credential_input: 'aws_ecr_signing_v1', enforcement: 'active'});
const catalog = () => ({schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false, hardwareVerified: false,
  revision: 1, policy: {policy_hash: hash(1), loaded_policy_hash: hash(1), sequence: 1, activation: 'active'},
  proxy_url: 'https://proxy.example.test', allowed_upstreams: ['https://api.ecr.us-east-1.amazonaws.com'],
  credentials: [credential()], applications: [application()], access_rules: [rule()],
  limits: Object.fromEntries(['credentials', 'applications', 'access_rules'].map(key => [key, {active: 1, retained: 1, active_max: 32, retained_max: 1024}])),
  capabilities: {credential_types: ['bearer', 'header'], response_modes: ['unfiltered_json_or_empty_v2'], credential_input_modes: ['insert', 'replace_exact'],
    request_body_modes: ['preserve_json_v1'], token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}, oauth: false,
    aws_credentials: {schema: 'serverware.operatorAwsCredentials/v1', connection_type: 'aws_sigv4_v1',
      create_path: '/api/operator-demo/credentials/aws-sigv4', replace_path: '/api/operator-demo/credentials/aws-sigv4/replace',
      revoke_path: '/api/operator-demo/credentials/revoke', credential_kinds: ['long_term', 'session'], signing_available: false, automatic_renewal: false},
    application_proxy_authentication: {schema: 'serverware.operatorProxyAuthentication/v1', path: '/api/operator-demo/applications/proxy-authentication',
      modes: ['bearer', 'basic_and_bearer_v1']}, ecr_publication: CAPABILITY}});
const artifact = () => ({schema: 'serverware.ecrVerifiedImage/v1',
  manifest: {media_type: 'application/vnd.oci.image.manifest.v1+json', digest: hash(10), size: 500},
  config: {media_type: 'application/vnd.oci.image.config.v1+json', digest: hash(11), size: 20},
  layers: [{media_type: 'application/vnd.oci.image.layer.v1.tar+gzip', digest: hash(12), size: 1024}],
  blobs: [{digest: hash(11), size: 20}, {digest: hash(12), size: 1024}], total_blob_bytes: 1044});
const publication = (patch = {}) => ({schema: 'serverware.ecrPublication/v1', id: IDS[3], status: 'awaiting_review', assurance: 'host-trusted',
  application_id: IDS[1], access_rule_id: IDS[2], principal_id: application().principal_id, route_id: rule().route_id, credential_id: IDS[0],
  credential_generation: 1, policy_hash: hash(1), scope: SCOPE, manifest_digest: hash(10), artifact_sha256: hash(13), artifact: artifact(),
  created_at_epoch_ms: NOW, expires_at_epoch_ms: NOW + 3600000, revision: 1, child: null, progress: null,
  artifacts_retired: false, artifact_retirement_status: 'available', artifacts_retired_at_epoch_ms: null,
  reviewer_id: null, decision_note: null, terminal_reason: null, ...patch});
function load() {
  const files = JSON.parse(execFileSync('python3', ['-B', '-c', 'import json; from serverware.operator_demo_portal import SCRIPT_FILES; print(json.dumps(SCRIPT_FILES))'],
    {cwd: ROOT, encoding: 'utf8', timeout: 5000}));
  const context = vm.createContext({module: {exports: {}}, URL, Date: class extends Date {static now() {return NOW;} }});
  for (const file of files) vm.runInContext(readFileSync(resolve(ROOT, 'serverware/operator_demo_web', file), 'utf8'), context, {timeout: 1000, filename: file});
  return context;
}
function main() {
  const api = load(), raw = catalog(), projected = api.projectCatalog(raw), key = projected.credentials[0], client = projected.applications[0], grant = projected.access_rules[0];
  // Exercise the actual backend descriptor with readiness stubbed, never a live
  // app/gate/database check. The independent literal detects drift on either side.
  const backend = JSON.parse(execFileSync('python3', ['-B', '-c', `
import json, sys
def deny_runtime(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in {'os.system', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('descriptor attempted runtime I/O')
sys.addaudithook(deny_runtime)
from serverware import operator_catalog_ecr as ecr
assert 'serverware.app' not in sys.modules and 'serverware.config' not in sys.modules
ecr._available = lambda policy_hash: True
print(json.dumps(ecr.capability('sha256:' + '0' * 64)))
`], {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 16384}));
  assert.deepEqual(backend, CAPABILITY, 'actual backend and independent capability fixture agree on every field');
  assert.deepEqual(copy(api.projectEcrCapability(backend)), backend, 'actual backend capability survives strict UI projection');
  const missingRouteScope = {...backend}; delete missingRouteScope.route_scope;
  assert.equal(api.projectEcrCapability(missingRouteScope), null);
  assert.deepEqual(copy(api.projectEcrCapability(CAPABILITY)), CAPABILITY);
  for (const patch of [{automatic_retries: true}, {source_pair_required: false}, {create_rule_path: 'https://other.test'},
    {publication_approval_required: false}, {route_scope: 'unrestricted'}, {unknown_field: true}])
    assert.equal(api.projectEcrCapability({...CAPABILITY, ...patch}), null);
  assert(api.operatorRuleSupported(grant, projected)); assert.equal(api.operatorRuleSupported(grant, {...projected, capabilities: {...projected.capabilities, ecr_publication: null}}), false);
  assert(api.ecrRuleValid(grant, key)); assert.equal(api.operatorRuleCredentialValid({...grant, operation_bundle: undefined}, key), false);
  for (const patch of [{approval_mode: 'automatic'}, {credential_input: 'insert'}, {placeholder: 'AWS key'}, {region: 'cn-north-1'}, {image_tag: ''}])
    assert.equal(api.ecrRuleValid({...grant, ...patch}, key), false);
  assert.equal(api.ecrAvailable(projected, {...key, expired: true}), false);
  assert.equal(api.ecrAvailable({...projected, allowed_upstreams: []}, key, grant), false);
  const unavailable = catalog(); unavailable.capabilities.ecr_publication = null;
  assert(api.projectCatalog(unavailable), 'retained typed permissions remain readable when readiness is unavailable');
  const config = copy(api.ecrClientConfig(projected, client, grant, 'synthetic-client-token', './serverware-ca.pem'));
  assert.equal(config.schema, 'serverware.awsEcrPublicationClient/v1'); assert.equal(config.control_api_url, 'https://proxy.example.test/v1/ecr/publications');
  assert.equal(config.expected_policy_hash, hash(1)); assert.equal(config.proxy_password, 'synthetic-client-token');
  for (const field of ['secret_access_key', 'access_key_id', 'session_token', 'publication_id', 'selected_publication_id', 'execute_write']) assert(!Object.hasOwn(config, field));
  assert.throws(() => api.ecrClientConfig(projected, {...client, proxy_authentication: 'bearer'}, grant, 'synthetic', './ca.pem'));
  const source = publication({secret_access_key: 'private-canary'}), publicValue = api.projectEcrPublication(source);
  assert(api.ecrPublicationCurrent(publicValue, projected));
  for (const patch of [{policy_hash: hash(99)}, {credential_generation: 2}, {route_id: 'different'}, {principal_id: 'different'}])
    assert.equal(api.ecrPublicationCurrent({...publicValue, ...patch}, projected), false);
  const collision = catalog(); collision.access_rules.push({...rule(), id: IDS[4], route_id: 'operator.' + IDS[4]});
  assert.throws(() => api.projectCatalog(collision));
  assert(!JSON.stringify(publicValue).includes('private-canary'));
  assert.equal(api.projectEcrPublication(publication({status: 'staging', artifact: null, revision: 0})).revision, 0);
  for (const patch of [{status: 'unrecognized'}, {artifact: null}, {manifest_digest: hash(99)}, {credential_generation: 0}, {scope: {...SCOPE, registry_id: 'other'}}])
    assert.throws(() => api.projectEcrPublication(publication(patch)));
  const badImage = artifact(); badImage.blobs[0].size++; assert.throws(() => api.projectEcrArtifact(badImage, hash(10)));
  assert.throws(() => api.projectEcrPublications({publications: [source, source]}));
  assert.equal(api.projectEcrPublications({publications: [source]}).next_cursor, null);
  assert.equal(api.projectEcrPublications({publications: [source], next_cursor: source.id}).next_cursor, source.id);
  for (const value of [{publications: [], next_cursor: IDS[3]}, {publications: [source], next_cursor: IDS[4]},
    {publications: [source], next_cursor: 'invalid'}, {publications: Array.from({length: 11}, (_, n) => publication({id: n.toString(16).padStart(8, '0') + '-4444-4444-8444-444444444444'}))}])
    assert.throws(() => api.projectEcrPublications(value));
  for (const status of ['published', 'denied', 'expired', 'failed']) {
    assert(api.ecrPublicationRetirable(api.projectEcrPublication(publication({status}))));
    assert(api.ecrPublicationRetirable(api.projectEcrPublication(publication({status, artifact_retirement_status: 'pending'}))));
    assert.equal(api.ecrPublicationRetirable(api.projectEcrPublication(publication({status, child: {id: IDS[4], action: 'PutImage', status: 'possible_send', request_sha256: hash(15)}}))), false);
  }
  for (const status of ['staging', 'awaiting_review', 'approved', 'active', 'suspended', 'uncertain'])
    assert.equal(api.ecrPublicationRetirable(api.projectEcrPublication(publication({status}))), false);
  const retired = api.projectEcrPublication(publication({status: 'published', artifacts_retired: true, artifact_retirement_status: 'retired', artifacts_retired_at_epoch_ms: NOW + 1}));
  assert.equal(api.ecrPublicationRetirable(retired), false);
  const legacy = publication({status: 'published'});
  for (const key of ['artifacts_retired', 'artifact_retirement_status', 'artifacts_retired_at_epoch_ms']) delete legacy[key];
  assert.equal(api.ecrPublicationRetirable(api.projectEcrPublication(legacy)), false);
  for (const patch of [{artifacts_retired: true}, {artifact_retirement_status: 'unknown'}, {artifact_retirement_status: 'pending'},
    {status: 'published', artifact_retirement_status: 'retired', artifacts_retired: true}, {artifacts_retired_at_epoch_ms: NOW}])
    assert.throws(() => api.projectEcrPublication(publication(patch)));
  const receipt = {publication: source, assurance: 'host-trusted', review_receipt_id: IDS[4], review_digest: hash(14), review_expires_at_epoch_ms: NOW + 60000};
  assert(api.projectEcrReview(receipt, publicValue));
  for (const patch of [{scope: {...SCOPE, image_tag: 'different'}}, {policy_hash: hash(99)}, {credential_generation: 2}, {id: IDS[4]}])
    assert.throws(() => api.projectEcrReview({...receipt, publication: publication(patch)}, publicValue));
  assert.throws(() => api.projectEcrReview({...receipt, review_expires_at_epoch_ms: NOW}, publicValue));
  console.log(JSON.stringify({ok: true, groups: 11, scope: 'actual backend/UI capability equality, typed scope, config, compound review, paging and local retirement contracts', network: false}));
}
if (require.main === module) main();
module.exports = {ROOT, NOW, IDS, SCOPE, CAPABILITY, hash, copy, credential, application, rule, catalog, artifact, publication, load};

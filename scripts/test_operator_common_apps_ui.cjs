#!/usr/bin/env node
'use strict';
// Pure public catalog/configuration checks. No browser, provider or app traffic.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const ROOT = resolve(__dirname, '..');
const source = execFileSync('python3', ['-B', '-c',
  'import json; from catchplate import operator_common_apps as a, operator_demo as d; from catchplate.operator_demo_portal import SCRIPT_FILES; d.settings=lambda: {"allowed_upstreams": list({op["origin"] for p in a.presets() for op in p["operations"]})}; print(json.dumps({"capability":a.capability(),"scripts":SCRIPT_FILES}))'],
  {cwd: ROOT, encoding: 'utf8', timeout: 5000});
const fixture = JSON.parse(source);
const context = vm.createContext({URL, URLSearchParams, module: {exports: {}}, location: {origin: 'https://operator.example.test'}});
for (const name of fixture.scripts) vm.runInContext(readFileSync(resolve(ROOT, 'catchplate/operator_demo_web', name), 'utf8'), context, {timeout: 1000, filename: name});
const copy = value => JSON.parse(JSON.stringify(value));
const capability = context.projectCommonAppsCapability(fixture.capability);
assert(capability); assert.equal(capability.presets.length, 12);
assert.equal(context.projectCommonAppsCapability({...fixture.capability, schema: 'unknown'}), null);
assert.equal(context.projectCommonAppsCapability({...fixture.capability, create_rule_path: 'https://elsewhere.invalid'}), null);
const duplicate = copy(fixture.capability); duplicate.presets.push(duplicate.presets[0]);
assert.equal(context.projectCommonAppsCapability(duplicate), null);
const cloudflare = capability.presets.find(item => item.id === 'cloudflare');
const visibleOperations = capability.presets.flatMap(preset => context.commonAppCreationOperations(preset));
assert.equal(visibleOperations.length, 15, 'new permission selectors retain the same visible operation count');
assert.deepEqual(copy(context.commonAppCreationOperations(cloudflare).map(item => item.id)), ['zones_sdk_v1', 'dns_records_sdk_v1']);
assert.deepEqual(copy(context.commonAppCreationOperations(cloudflare).map(item => item.label)), ['List zones', 'Read DNS records in one zone']);
assert.equal(cloudflare.operations.length, 4, 'legacy descriptors remain in the advertised catalog');
assert.equal(context.commonAppCreationOperations(null).length, 0);
for (const id of ['zones', 'dns_records']) assert.equal(cloudflare.operations.find(item => item.id === id).available_for_creation, false);
const legacyOnly = {...cloudflare, operations: cloudflare.operations.filter(item => item.available_for_creation === false)};
assert.equal(context.commonAppCreationOperations(legacyOnly).length, 0);
const omittedFlag = copy(cloudflare.operations[0]); delete omittedFlag.available_for_creation;
assert.equal(context.commonAppCreationOperations({operations: [omittedFlag]})[0].id, omittedFlag.id, 'absent marker remains compatible');
for (const malformed of [null, 'false', 0, 1, {}, []]) {
  const invalid = copy(fixture.capability); invalid.presets.find(item => item.id === 'cloudflare').operations[0].available_for_creation = malformed;
  assert.equal(context.projectCommonAppsCapability(invalid), null);
}
const samples = {model: 'test-model', max_output_tokens: 256, channel: 'C0123456789', channel_id: '123456789012345678',
  page_id: '01234567-89ab-cdef-0123-456789abcdef', block_id: '01234567-89ab-cdef-0123-456789abcdef',
  sender: 'alerts@example.com', recipient: 'operator@example.com', project_id: '12345',
  zone_id: '0123456789abcdef0123456789abcdef', organization: 'my-organization'};
const ids = {credential: '11111111-1111-4111-8111-111111111111', app: '22222222-2222-4222-8222-222222222222'};
let operations = 0;
for (const preset of capability.presets) for (const operation of preset.operations) {
  const scope = Object.fromEntries(operation.scope_fields.map(field => [field.key, samples[field.key]]));
  if (preset.id === 'openrouter') scope.model = 'test-provider/test-model';
  const credential = {id: ids.credential, name: 'Saved key', status: 'active', app_preset: preset.id, auth_type: preset.auth_type, header_name: preset.header_name};
  const app = {id: ids.app, status: 'active', proxy_authentication: 'bearer'};
  const catalog = {credentials: [credential], applications: [app], allowed_upstreams: [operation.origin],
    capabilities: {common_apps: capability, response_modes: ['unfiltered_json_or_empty_v2'], credential_input_modes: ['replace_exact'],
      host_approvals: {available: true, generic_rules: true, operation_bundles: []}}};
  const rule = {...context.commonAppRuleFields(preset, operation.id, scope), name: operation.label, application_id: app.id, credential_id: credential.id};
  assert.equal(context.commonAppOperation(catalog, rule).id, operation.id, 'saved operation lookup includes legacy profiles');
  assert(context.commonAppAvailable(catalog, credential, operation.id), 'legacy profile remains available to its existing rules');
  assert(context.commonAppRuleValid(rule, credential, catalog), preset.id);
  assert(context.operatorRuleContentValid(rule, credential), preset.id);
  assert(context.operatorRuleSupported(rule, catalog), preset.id);
  assert(context.operatorRuleSupported({...rule, approval_mode: 'host_review_v1'}, catalog));
  assert(!context.commonAppRuleValid({...rule, upstream_url: rule.upstream_url + '/other'}, credential, catalog));
  assert(!context.commonAppRuleValid({...rule, request_body_mode: 'preserve_json_v1'}, credential, catalog));
  assert(!context.operatorRuleSupported(rule, {...catalog, allowed_upstreams: []}));
  assert(!context.operatorRuleContentValid({...rule, app_preset: undefined}, {...credential, app_preset: undefined}) ||
    !context.commonAppRuleValid({...rule, app_preset: undefined}, credential, catalog));
  const request = context.commonAppRequest(rule, catalog);
  assert.equal(request.headers[preset.header_name], preset.placeholder);
  assert(!JSON.stringify(request).includes('$scope'));
  const command = context.commonAppCurlCommand({proxyUrl: 'https://proxy.example.test', upstreamUrl: rule.upstream_url,
    method: rule.methods[0], caPath: "./ca's.pem", allowedHeaders: rule.allowed_headers, credentialInput: rule.credential_input,
    placeholder: rule.placeholder, credential}, rule, catalog);
  assert(command.includes(preset.placeholder)); assert(!command.includes('--insecure')); assert(!command.includes('--retry'));
  if (rule.methods[0] === 'POST') assert(command.includes('--data-binary'));
  if (preset.id === 'sentry') assert(command.includes('?project=12345'));
  if (preset.id === 'discord') assert(command.includes('Authorization: Bot catchplate-discord-placeholder-v1'));
  const payload = copy(context.commonAppRulePayload(rule));
  assert.deepEqual(Object.keys(payload).sort(), ['app_preset', 'application_id', 'credential_id', 'name', 'operation', 'scope']);
  assert.equal(payload.operation, operation.id);
  const missing = {...scope, unexpected: 'field'}; assert.throws(() => context.commonAppRuleFields(preset, operation.id, missing));
  operations++;
}
const connect = readFileSync(resolve(ROOT, 'catchplate/operator_demo_web/workspace_connect.js'), 'utf8');
assert.equal(operations, 17, 'all new and retained legacy descriptors remain valid and exportable');
assert(connect.includes('commonAppCreationOperations(commonPreset()).map(item => ({id: item.id, name: item.label}))'));
assert(connect.includes('commonAppCreationOperations(commonPreset()).find(item => item.id === element(\'connect-operation\').value)'));
// Execute the actual creation draft function with inert scope inputs. This
// catches injected legacy select values without mounting a browser or posting.
const draftStart = connect.indexOf('  function draftRule() {');
const draftEnd = connect.indexOf("\n  element('connect-access-form').addEventListener", draftStart);
assert(draftStart > 0 && draftEnd > draftStart);
const cloudflareCredential = {id: ids.credential, status: 'active', app_preset: 'cloudflare', auth_type: cloudflare.auth_type, header_name: cloudflare.header_name};
const cloudflareCatalog = {credentials: [cloudflareCredential], applications: [{id: ids.app, status: 'active', proxy_authentication: 'bearer'}], allowed_upstreams: ['https://api.cloudflare.com'],
  capabilities: {common_apps: capability, response_modes: ['unfiltered_json_or_empty_v2'], credential_input_modes: ['replace_exact']}};
Object.assign(context, {credential: () => cloudflareCredential, commonPreset: () => cloudflare, catalog: () => cloudflareCatalog,
  selectedApplication: ids.app, selectedCredential: ids.credential, supported: rule => context.operatorRuleSupported(rule, cloudflareCatalog)});
for (const operationId of ['zones_sdk_v1', 'dns_records_sdk_v1', 'zones', 'dns_records']) {
  context.document = {getElementById: id => ({value: id === 'connect-operation' ? operationId : samples[id.replace('connect-common-scope-', '')]})};
  const run = () => vm.runInContext('(' + connect.slice(draftStart, draftEnd).trim() + ')()', context, {timeout: 1000});
  if (operationId.endsWith('_sdk_v1')) assert.equal(run().app_operation, operationId);
  else assert.throws(run, 'legacy operation cannot be injected into a new permission draft');
}
assert(connect.includes("'access-rules/common-app'"));
assert(connect.includes('commonAppRulePayload(result[key]), commonAppRulePayload(review.rule)'));
assert(connect.includes('commonPolicyHash: result.policy.policy_hash'));
const handoff = readFileSync(resolve(ROOT, 'catchplate/operator_demo_web/workspace_proxy_audit.js'), 'utf8');
for (const field of ['common_app:', 'request_body: request.body', 'request_query: request.query', 'automatic_retries: 0']) assert(handoff.includes(field));
console.log(JSON.stringify({ok: true, providers: capability.presets.length, operations, visibleOperations: visibleOperations.length, groups: 11,
  scope: 'pure catalog, derived authority, public request examples and download contract; no provider or browser traffic'}));

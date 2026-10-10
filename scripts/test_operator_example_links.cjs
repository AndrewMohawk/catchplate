#!/usr/bin/env node
// Inert public-code discovery checks only. No browser, HTTP, application,
// generated recipe, package installation, provider or Git command is run.
const assert = require('node:assert/strict');
const {readFileSync, statSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {context, rawCatalog, npmRule, clone, IDS} = require('./test_operator_npm_ui.cjs');
const {capability: publishCapability, publishRule} = require('./test_operator_npm_publish_ui.cjs');
const {credential, application, rule} = require('./test_operator_catalog_browser.cjs');
const {google} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const BASE = 'https://github.com/AndrewMohawk/serverware/';
const BRANCH = 'serverware/operator-workspace/';
const HTML = readFileSync(resolve(ROOT, 'serverware/operator_demo_web/index.html'), 'utf8');
const PROXY = readFileSync(resolve(ROOT, 'serverware/operator_demo_web/workspace_proxy_audit.js'), 'utf8');
const f = context();
let networkCalls = 0;
f.value.fetch = () => { networkCalls++; throw new Error('No network permitted'); };
vm.runInContext(PROXY, f.value, {timeout: 1000});
const links = value => clone(f.run('operatorExampleProjects(input.access_rules[0], input)', value));
const node = id => f.dom.getElementById(id);
const render = value => f.run('renderOperatorExampleProjects(input?.access_rules[0], input)', value);

function github(bundle = 'github_issues_read_v1') {
  const origin = 'https://api.github.com';
  const saved = rule({operation_bundle: bundle, repository: {owner: 'Example', name: 'Repository'},
    upstream_url: origin + '/repos/Example/Repository/issues', methods: bundle === 'github_issues_write_v1' ? ['GET', 'POST'] : ['GET'],
    request_fields: [], response_fields: [], query_keys: ['assignee', 'creator', 'direction', 'labels', 'mentioned', 'milestone', 'page', 'per_page', 'since', 'sort', 'state'],
    allowed_headers: ['accept', 'accept-language', 'sec-fetch-mode', 'user-agent', 'x-github-api-version'],
    request_body_mode: 'preserve_json_v1', query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2',
    credential_input: 'replace_exact', placeholder: 'token serverware-github-placeholder-v1'});
  const value = rawCatalog({credentials: [credential({connection_type: 'github_token_v1', provider_id: 'github'})], rules: [saved], allowed: [origin]});
  value.capabilities.github = {schema: 'serverware.operatorGithub/v1', connection_type: 'github_token_v1',
    create_credential_path: '/api/operator-demo/credentials/github-token', create_rule_path: '/api/operator-demo/access-rules/github',
    api_origin: origin, destination_allowed: true, operation_bundles: ['github_issues_read_v1', 'github_issues_write_v1'],
    sdk_auth_token: 'serverware-github-placeholder-v1', placeholder: 'token serverware-github-placeholder-v1',
    query_mode: 'githubRestV1', response_mode: 'unfiltered_json_or_empty_v2', source_pair_required: true};
  return value;
}
function gmail() {
  const fields = clone(f.run('gmailRuleFields()'));
  const value = rawCatalog({credentials: [google()], rules: [rule({...fields, credential_input: 'insert'})],
    allowed: ['https://gmail.googleapis.com']});
  // Public, already-projected capability input: this suite tests discovery,
  // not OAuth admission. The existing Google suites own that closed contract.
  value.capabilities.google_oauth = {permission_preset: 'gmail_readonly'};
  value.capabilities.operation_bundles = [clone(f.run('operatorGmailDescriptor()'))];
  return value;
}
function publishing() {
  const value = rawCatalog({rules: [publishRule()]}); value.capabilities.npm_publish = publishCapability(); return value;
}
const tests = [
  ['provider-first entry choices preserve the existing controls and forms', () => {
    for (const [id, label] of [['connect-use-github', 'GitHub'], ['connect-use-npm', 'npm'], ['connect-use-key', 'Manual API key']])
      assert.match(HTML, new RegExp('<button id="' + id + '"[^>]*>' + label + '</button>'));
    assert.equal([...HTML.matchAll(/id="connect-credential-form"/g)].length, 1);
    assert.equal([...HTML.matchAll(/id="credential-form"/g)].length, 1);
    assert(!/id="connect-use-(?:alchemy|twitter|actions)"/.test(HTML));
    assert(HTML.indexOf('id="client-examples"') > HTML.indexOf('id="download-config"'));
  }],
  ['both validated GitHub bundles link only the three public project directories', () => {
    for (const bundle of ['github_issues_read_v1', 'github_issues_write_v1']) {
      const found = links(github(bundle));
      assert.deepEqual(found.map(item => item.label), ['Node.js + GitHub Actions', 'Python', 'Go']);
      assert.deepEqual(found.map(item => item.href), ['node', 'python', 'go'].map(language =>
        BASE + 'tree/' + BRANCH + 'examples/github-issues-' + language));
      assert(found.every(item => item.kind === 'project'));
    }
  }],
  ['npm and Gmail link existing verification guides rather than nonexistent projects', () => {
    for (const [value, filename] of [[rawCatalog({rules: [npmRule()]}), 'operator-npm-metadata.md'],
      [publishing(), 'operator-npm-publish.md'], [gmail(), 'operator-gmail-job-verification.md']]) {
      const found = links(value); assert.equal(found.length, 1); assert.equal(found[0].kind, 'guide');
      assert.equal(found[0].href, BASE + 'blob/' + BRANCH + 'docs/' + filename);
      assert(statSync(resolve(ROOT, 'docs', filename)).isFile());
      render(value); assert.match(node('client-example-note').textContent, /not a runnable example project/);
    }
  }],
  ['a bundle label alone, revoked resources, or absent source capability never selects examples', () => {
    for (const change of [value => { value.capabilities.github = null; },
      value => { value.capabilities.github.source_pair_required = false; },
      value => { value.capabilities.github.destination_allowed = false; }, value => { value.allowed_upstreams = []; },
      value => { value.access_rules[0].status = 'revoked'; }, value => { value.credentials[0].status = 'revoked'; },
      value => { value.applications[0].status = 'revoked'; }, value => { value.access_rules[0].methods = ['DELETE']; },
      value => { value.access_rules[0].repository.owner = '*'; }, value => { value.access_rules[0].placeholder = 'Bearer wrong'; },
      value => { value.access_rules[0].operation_bundle = 'constructor'; }, value => { value.access_rules[0].operation_bundle = '__proto__'; }]) {
      const value = github(); change(value); assert.deepEqual(links(value), []);
    }
    const manual = rawCatalog({credentials: [credential()], rules: [rule()]});
    assert.deepEqual(links(manual), []);
  }],
  ['public links remain readable with an expired app token, without weakening recipe guards', () => {
    const value = github(); const expected = links(value);
    value.applications[0] = application({...value.applications[0], token_status: 'expired', token_expires_at_epoch_ms: 1});
    assert.deepEqual(links(value), expected);
    assert(PROXY.indexOf('renderOperatorExampleProjects(rule, catalog);', PROXY.indexOf('function createProxyView')) <
      PROXY.indexOf('if (!valid || !supported || credential?.status'));
    assert.match(PROXY, /element\('copy-command'\)\.disabled = !ready/);
    assert.match(PROXY, /element\('download-config'\)\.disabled = !ready \|\| !applications\.tokenFor\(application\.id\)/);
  }],
  ['links never interpolate IDs, private tokens, custom URLs, query strings or fragments', () => {
    const value = github(); const expected = links(value);
    value.proxy_url = 'https://PRIVATE_TOKEN@private.example.test/?PRIVATE_QUERY';
    value.credentials[0].secret = 'PROVIDER_SECRET_CANARY'; value.applications[0].token = 'APP_SECRET_CANARY';
    value.access_rules[0].example_url = 'https://untrusted.example.test';
    assert.deepEqual(links(value), expected);
    for (const link of links(value)) {
      const url = new URL(link.href); assert.equal(url.origin, 'https://github.com');
      assert.equal(url.username + url.password + url.search + url.hash, '');
      for (const forbidden of [IDS.application, IDS.credential, IDS.rule, 'PRIVATE_', 'SECRET_CANARY', 'untrusted.example.test'])
        assert(!link.href.includes(forbidden));
    }
  }],
  ['rendered inert anchors are explicit public navigation and stale links are removed', () => {
    render(github()); assert.equal(node('client-examples').hidden, false);
    assert.match(node('client-example-note').textContent, /README.*verification status/);
    assert.match(node('client-example-note').textContent, /separate from your private client config/);
    for (const anchor of node('client-example-links').children) {
      assert.equal(anchor.tag, 'a'); assert.equal(anchor.target, '_blank');
      assert.equal(anchor.rel, 'noopener noreferrer'); assert.equal(anchor.referrerPolicy, 'no-referrer');
      assert.equal(anchor.download, undefined); assert.deepEqual(anchor.events, {});
    }
    render(null); assert.equal(node('client-examples').hidden, true);
    assert.equal(node('client-example-links').children.length, 0); assert.equal(node('client-example-note').textContent, '');
    assert.match(PROXY, /function render\(\) \{\s*command = '';[^\n]*\n\s*renderOperatorExampleProjects\(null, null\)/);
    assert.equal(networkCalls, 0);
  }],
  ['all advertised project directories contain a README in the source snapshot', () => {
    for (const language of ['node', 'python', 'go'])
      assert(statSync(resolve(ROOT, 'examples', 'github-issues-' + language, 'README.md')).isFile());
  }],
];
function main() {
  assert.equal(process.argv.length, 2, 'No browser or live target arguments accepted');
  for (const [name, test] of tests) { test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, generated_recipe_executed: false}));
}
if (require.main === module) main();

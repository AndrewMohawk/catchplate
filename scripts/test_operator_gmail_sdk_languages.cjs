#!/usr/bin/env node
// Pure configuration and generated-shell tests. Only inert local interpreter
// stubs execute: no SDK, network, browser, credential store or provider access.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync} = require('node:fs');
const {tmpdir} = require('node:os');
const {join, resolve} = require('node:path');
const vm = require('node:vm');

const ROOT = resolve(__dirname, '..');
const source = readFileSync(join(ROOT, 'catchplate/operator_demo_web/workspace_gmail_sdk.js'), 'utf8');
const helpers = vm.runInNewContext(source + '\n({gmailSdkLanguage, gmailSdkPublicConfiguration, buildGmailSdkClientRecipe, gmailSdkClientConfiguration, gmailSdkFileCommand});', {}, {timeout: 1000});
const clone = value => JSON.parse(JSON.stringify(value));
const TOKEN = Buffer.alloc(32, 85).toString('base64url');
const NOW = 1800000000000;
const input = {proxyUrl: 'https://proxy.example.test', applicationId: '11111111-1111-4111-8111-111111111111',
  accessRuleId: '22222222-2222-4222-8222-222222222222', tokenExpiresAtEpochMs: NOW + 86400000,
  nowEpochMs: NOW, caPath: './catchplate-ca.pem', proxyCaPath: ''};
const observed = [];
function test(name, body) { body(); observed.push(name); }

test('downloaded config commands are fixed, language-specific and secret-free', () => {
  for (const [language, command] of [
    ['go', './gmail-example'], ['node', 'node client.mjs'], ['python', '.venv/bin/python -I -B gmail.py'],
  ]) {
    assert.equal(helpers.gmailSdkFileCommand(language), command + ' --config ./catchplate-client.private.json');
    assert(!helpers.gmailSdkFileCommand(language).includes(TOKEN));
  }
  for (const language of ['node; echo unwanted', '__proto__', '', null])
    assert.throws(() => helpers.gmailSdkFileCommand(language));
});

test('closed languages and unchanged Go v1 default', () => {
  const expected = {schema: 'catchplate.gmailSdkClient/v1', example_directory: 'examples/google-gmail-go',
    entrypoint: './gmail-example', clear_environment: true, environment: {LANG: 'C.UTF-8',
      CATCHPLATE_PROXY_URL: input.proxyUrl, CATCHPLATE_APP_ID: input.applicationId, CATCHPLATE_CA_FILE: input.caPath},
    token_expires_at_epoch_ms: input.tokenExpiresAtEpochMs, access_rule_id: input.accessRuleId};
  assert.deepEqual(clone(helpers.gmailSdkPublicConfiguration(input)), expected);
  assert.deepEqual(clone(helpers.gmailSdkPublicConfiguration({...input, language: 'go'})), expected);
  assert.equal(helpers.buildGmailSdkClientRecipe(input), helpers.buildGmailSdkClientRecipe({...input, language: 'go'}));
  for (const language of ['', null, false, [], {}, 'Node', 'constructor', '__proto__', 'node; echo unwanted'])
    assert.throws(() => helpers.gmailSdkPublicConfiguration({...input, language}));
});

test('restricted copied recipes carry only the validated age hint; private recipe schema stays unchanged', () => {
  for (const language of ['go', 'node', 'python']) {
    const plain = helpers.buildGmailSdkClientRecipe({...input, language});
    assert.equal(helpers.buildGmailSdkClientRecipe({...input, language, agePolicy: {mode: 'unrestricted'}}), plain);
    for (const days of [1, 30, 3650]) {
      const options = {...input, language, agePolicy: {mode: 'recent_internal_date_v1', max_age_days: days}};
      const recipe = helpers.buildGmailSdkClientRecipe(options);
      assert(recipe.includes('export CATCHPLATE_GMAIL_MAX_AGE_DAYS='));
      assert.deepEqual(clone(helpers.gmailSdkPublicConfiguration(options)), clone(helpers.gmailSdkPublicConfiguration({...input, language})));
      assert(!Object.hasOwn(helpers.gmailSdkClientConfiguration(options, TOKEN).environment, 'CATCHPLATE_GMAIL_MAX_AGE_DAYS'));
    }
    for (const agePolicy of [null, {}, {mode: 'recent_internal_date_v1', max_age_days: 0},
      {mode: 'recent_internal_date_v1', max_age_days: '30'}, {mode: 'recent_internal_date_v1', max_age_days: 3651},
      {mode: 'unrestricted', max_age_days: 30}, {mode: 'recent_internal_date_v1', max_age_days: 30, extra: true}])
      assert.throws(() => helpers.buildGmailSdkClientRecipe({...input, language, agePolicy}));
  }
});

test('versioned interpreted profiles match actual checked-in entrypoints', () => {
  for (const [language, entrypoint, args, filename] of [
    ['node', 'node', ['client.mjs'], 'client.mjs'],
    ['python', '.venv/bin/python', ['-I', '-B', 'gmail.py'], 'gmail.py'],
  ]) {
    const value = clone(helpers.gmailSdkPublicConfiguration({...input, language}));
    assert.deepEqual(Object.keys(value).sort(), ['schema', 'language', 'arguments', 'resolve_ca_paths', 'resolve_executable_from_path',
      'example_directory', 'entrypoint', 'clear_environment', 'environment', 'token_expires_at_epoch_ms', 'access_rule_id'].sort());
    assert.equal(value.schema, 'catchplate.gmailSdkClient/v2'); assert.equal(value.language, language);
    assert.equal(value.entrypoint, entrypoint); assert.deepEqual(value.arguments, args);
    assert.equal(value.example_directory, 'examples/google-gmail-' + language);
    assert(value.resolve_ca_paths && value.clear_environment);
    assert.equal(value.resolve_executable_from_path, language === 'node');
    assert(readFileSync(join(ROOT, value.example_directory, filename), 'utf8').length > 0);
    value.arguments.push('mutated'); value.environment.CATCHPLATE_APP_ID = 'mutated';
    assert.deepEqual(clone(helpers.gmailSdkPublicConfiguration({...input, language})).arguments, args);
    assert.equal(helpers.gmailSdkPublicConfiguration({...input, language}).environment.CATCHPLATE_APP_ID, input.applicationId);
  }
});

test('public recipes contain no supplied secrets; private configuration is explicit', () => {
  for (const language of ['go', 'node', 'python']) {
    const command = helpers.buildGmailSdkClientRecipe({...input, language, token: TOKEN, providerSecret: 'synthetic-never-render'});
    assert(!command.includes(TOKEN)); assert(!command.includes('synthetic-never-render'));
    assert(!command.includes('HTTPS_PROXY=')); assert(!command.includes('NODE_TLS_REJECT_UNAUTHORIZED'));
    const privateConfig = helpers.gmailSdkClientConfiguration({...input, language}, TOKEN);
    assert.equal(privateConfig.environment.CATCHPLATE_PROXY_TOKEN, TOKEN);
    assert(!Object.hasOwn(helpers.gmailSdkPublicConfiguration({...input, language}).environment, 'CATCHPLATE_PROXY_TOKEN'));
    for (const token of ['', TOKEN + 'A', TOKEN.slice(0, -1) + 'B', 'bad\nvalue', null])
      assert.throws(() => helpers.gmailSdkClientConfiguration({...input, language}, token));
    for (const [key, values] of [['caPath', ['', 'bad\npath', 'bad\0path', 'x'.repeat(513), null]],
      ['proxyCaPath', ['bad\rpath', null]], ['proxyUrl', ['http://proxy.example.test', 'https://user:pass@proxy.example.test']],
      ['tokenExpiresAtEpochMs', [NOW, NaN]]]) for (const value of values)
        assert.throws(() => helpers.buildGmailSdkClientRecipe({...input, language, [key]: value}));
  }
});

const directory = mkdtempSync(join(tmpdir(), 'catchplate-gmail-language-test-'));
try {
  const runtime = join(directory, 'runtime with spaces'); mkdirSync(runtime);
  const project = join(directory, "project ' quoted"); mkdirSync(project);
  mkdirSync(join(project, '.venv', 'bin'), {recursive: true});
  // /bin/sh only sees this exact generated stub. It prints synthetic state for
  // assertions, never performs a request or loads an actual client SDK.
  const stub = '#!' + process.execPath + '\n' + [
    "const fs = require('node:fs');",
    "const input = fs.readFileSync(0, 'utf8');",
    "const token = process.env.CATCHPLATE_PROXY_TOKEN || '';",
    "const parent = fs.readFileSync('/proc/' + process.ppid + '/cmdline', 'utf8');",
    'process.stdout.write(JSON.stringify({environment: process.env, args: process.argv.slice(2), input,',
    'tokenInArgv: process.argv.some(value => value.includes(token)), tokenInParentArgv: parent.includes(token)}));',
  ].join('\n');
  for (const filename of [join(runtime, 'node'), join(project, '.venv', 'bin', 'python'), join(project, 'gmail-example')])
    writeFileSync(filename, stub, {flag: 'wx', mode: 0o700});
  const inner = "inner 'quoted' $(touch should-not-exist).pem";
  const outer = "outer ; literal.pem";
  for (const name of [inner, outer]) writeFileSync(join(project, name), 'synthetic public CA fixture', {flag: 'wx', mode: 0o600});
  const env = {PATH: runtime + ':/usr/bin:/bin', CATCHPLATE_PROXY_TOKEN: TOKEN,
    HTTPS_PROXY: 'http://unwanted.invalid', HTTP_PROXY: 'http://unwanted.invalid', ALL_PROXY: 'http://unwanted.invalid', NO_PROXY: '*',
    GOOGLE_APPLICATION_CREDENTIALS: '/not-a-credential', GOOGLE_API_USE_MTLS_ENDPOINT: 'always',
    NODE_OPTIONS: '--require=/must-not-load', SSLKEYLOGFILE: '/must-not-write', PYTHONPATH: '/must-not-import',
    SSL_CERT_FILE: '/must-not-read', SSL_CERT_DIR: '/must-not-read', DEBUG: 'must-not-log'};
  function execute(language, changes = {}, environment = env) {
    const command = helpers.buildGmailSdkClientRecipe({...input, language, caPath: './' + inner, proxyCaPath: './' + outer, ...changes});
    const result = execFileSync('/bin/bash', ['--noprofile', '--norc', '-c', command],
      {cwd: project, env: environment, timeout: 5000, maxBuffer: 16384, encoding: 'utf8', killSignal: 'SIGKILL', stdio: ['pipe', 'pipe', 'pipe']});
    return JSON.parse(result);
  }
  for (const language of ['go', 'node', 'python']) test(language + ' copied shell invokes only selected local stub with clean environment and EOF stdin', () => {
    const value = execute(language);
    assert.deepEqual(value.args, language === 'node' ? ['client.mjs'] : language === 'python' ? ['-I', '-B', 'gmail.py'] : []);
    assert.equal(value.input, ''); assert.equal(value.tokenInArgv, false); assert.equal(value.tokenInParentArgv, false);
    assert.deepEqual(value.environment, {LANG: 'C.UTF-8', CATCHPLATE_PROXY_TOKEN: TOKEN,
      CATCHPLATE_PROXY_URL: input.proxyUrl, CATCHPLATE_APP_ID: input.applicationId,
      CATCHPLATE_CA_FILE: language === 'go' ? './' + inner : join(project, inner),
      CATCHPLATE_PROXY_CA_FILE: language === 'go' ? './' + outer : join(project, outer)});
  });
  for (const language of ['go', 'node', 'python']) test(language + ' restricted copied shell supplies explicit days in its clean child only', () => {
    const value = execute(language, {agePolicy: {mode: 'recent_internal_date_v1', max_age_days: 30}});
    assert.equal(value.environment.CATCHPLATE_GMAIL_MAX_AGE_DAYS, '30');
    assert.equal(value.tokenInArgv, false); assert.equal(value.tokenInParentArgv, false);
  });
  test('interpreted recipes refuse unresolved CA, directories, absent runtime and invalid token before launch', () => {
    function refused(fn) {
      assert.throws(fn, error => error.status !== 0 && error.stdout === '', 'no interpreter-stub output');
    }
    for (const language of ['node', 'python']) {
      refused(() => execute(language, {caPath: './missing.pem'}));
      refused(() => execute(language, {caPath: '.'}));
      refused(() => execute(language, {}, {...env, CATCHPLATE_PROXY_TOKEN: ''}));
      refused(() => execute(language, {}, {...env, CATCHPLATE_PROXY_TOKEN: 'bad\nvalue'}));
      const result = execute(language, {proxyCaPath: ''});
      assert(!Object.hasOwn(result.environment, 'CATCHPLATE_PROXY_CA_FILE'));
    }
    refused(() => execute('node', {}, {...env, PATH: '/no-runtime-here'}));
    assert.throws(() => readFileSync(join(project, 'should-not-exist')), {code: 'ENOENT'});
  });
} finally {
  // Only the exact private mkdtemp directory created above is removed.
  rmSync(directory, {recursive: true, force: true});
}
console.log(JSON.stringify({ok: true, scope: 'pure UI helper and inert local shell stubs', groups: observed.length,
  browser: false, sdk: false, providerRequests: 0}));

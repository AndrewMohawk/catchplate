// Built-in-only checks, with mocks and one private temporary-file copy test.
// No npm execution, network, provider credential, proxy or public registry.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration, npmArguments, npmConfiguration, childEnvironment, reviewedProject, installationSummary } from './core.mjs';
import { createInstallationProject } from './client.mjs';
import { perform } from './worker.mjs';

const env = {
  CATCHPLATE_PROXY_URL: 'https://proxy.example.invalid:8443',
  CATCHPLATE_APP_ID: '01234567-89ab-4cde-8fab-0123456789ab',
  CATCHPLATE_PROXY_TOKEN: 'private_application_token_canary', CATCHPLATE_CA_FILE: '/trusted/inner.pem',
  CATCHPLATE_NPM_PACKAGE: '@example/package', CATCHPLATE_NPM_VERSION: '1.2.3',
  CATCHPLATE_NPM_PROJECT: '/reviewed/project', CATCHPLATE_NPM_OUTPUT: '/private/new-output',
};
const manifest = {name: 'catchplate-consumer', version: '1.0.0', private: true, dependencies: {'@example/package': '1.2.3'}};
const manifestBytes = Buffer.from(JSON.stringify(manifest));
const lock = {name: manifest.name, version: manifest.version, lockfileVersion: 3, packages: {
  '': {name: manifest.name, version: manifest.version, dependencies: manifest.dependencies},
  'node_modules/@example/package': {version: '1.2.3', resolved: 'https://registry.npmjs.org/@example/package/-/package-1.2.3.tgz',
    integrity: 'sha512-' + createHash('sha512').update('synthetic tarball').digest('base64')},
}};
const lockBytes = Buffer.from(JSON.stringify(lock));
const installedBytes = Buffer.from(JSON.stringify({name: '@example/package', version: '1.2.3'}));
const summary = {added: 1, audited: 2, audit: {dependencies: {total: 1},
  vulnerabilities: {info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0}}};
const paths = {root: '/private/task', project: env.CATCHPLATE_NPM_OUTPUT, cache: '/private/task/cache',
  trust: '/private/task/trust.pem', npmCli: '/example/node_modules/npm/bin/npm-cli.js',
  npmrc: '/private/task/user.npmrc', globalrc: '/private/task/global.npmrc'};

test('install and ci require separate absolute reviewed input and fresh output paths', () => {
  for (const operation of ['install', 'ci']) {
    const config = configuration(env, operation);
    assert.equal(config.project, env.CATCHPLATE_NPM_PROJECT);
    assert.equal(config.output, env.CATCHPLATE_NPM_OUTPUT);
    for (const patch of [{CATCHPLATE_NPM_PROJECT: undefined}, {CATCHPLATE_NPM_OUTPUT: undefined},
      {CATCHPLATE_NPM_OUTPUT: env.CATCHPLATE_NPM_PROJECT}, {CATCHPLATE_NPM_OUTPUT: '/'},
      {CATCHPLATE_NPM_OUTPUT: env.CATCHPLATE_NPM_PROJECT + '/nested-output'},
      {CATCHPLATE_NPM_OUTPUT: '../relative'}, {CATCHPLATE_NPM_PROJECT: '/reviewed/../project'}])
      assert.throws(() => configuration({...env, ...patch}, operation));
  }
});

test('stock CLI keeps audit default on, visible errors, disabled scripts, no tokens in argv', () => {
  for (const operation of ['install', 'ci']) {
    const config = configuration(env, operation), args = npmArguments(config, paths), npmrc = npmConfiguration(config);
    assert.ok(args.includes(operation));
    for (const flag of ['--ignore-scripts=true', '--fund=false', '--workspaces=false', '--json']) assert.ok(args.includes(flag));
    assert.ok(!args.some(value => /audit/.test(value)) && !/audit=/.test(npmrc));
    assert.ok(npmrc.includes('loglevel=error') && !npmrc.includes('loglevel=silent'));
    assert.ok(!JSON.stringify(args).includes(config.token) && !npmrc.includes(config.token));
    assert.equal(childEnvironment(config, paths).CATCHPLATE_NPM_OUTPUT, paths.project);
  }
});

test('project and lock review reject alternate sources and hidden configuration', () => {
  reviewedProject(configuration(env, 'install'), manifestBytes);
  reviewedProject(configuration(env, 'ci'), manifestBytes, lockBytes);
  assert.throws(() => reviewedProject(configuration(env, 'ci'), manifestBytes));
  for (const patch of [{private: false}, {scripts: {postinstall: 'never-run'}}, {workspaces: ['*']},
    {dependencies: {'@example/package': 'https://other.invalid/package.tgz'}}, {dependencies: {'@example/package': '^1.2.3'}}])
    assert.throws(() => reviewedProject(configuration(env, 'install'), Buffer.from(JSON.stringify({...manifest, ...patch}))));
  for (const patch of [{resolved: 'https://other.invalid/package.tgz'}, {link: true}, {integrity: 'wrong'},
    {resolved: 'https://registry.npmjs.org/@example/package/-/package.tgz?token=bad'},
    {dependencies: {other: 'git+https://other.invalid/repo'}}, {optionalDependencies: {other: 'file:/tmp/untrusted'}},
    {peerDependencies: {other: 'https://other.invalid/package.tgz'}}]) {
    const altered = structuredClone(lock);
    Object.assign(altered.packages['node_modules/@example/package'], patch);
    assert.throws(() => reviewedProject(configuration(env, 'ci'), manifestBytes, Buffer.from(JSON.stringify(altered))));
  }
});

test('exit-zero without actual audit metadata is not installation success', () => {
  const config = configuration(env, 'install');
  assert.equal(installationSummary(config, summary, installedBytes, lockBytes, manifestBytes).defaultAuditReportedSuccess, true);
  for (const value of [{added: 1, audited: 0}, {...summary, audit: null}, {...summary, audited: 0},
    {...summary, audit: {...summary.audit, vulnerabilities: {...summary.audit.vulnerabilities, total: 1}}}])
    assert.throws(() => installationSummary(config, value, installedBytes, lockBytes, manifestBytes));
  assert.throws(() => installationSummary(config, summary, Buffer.from('{"name":"other","version":"1.2.3"}'), lockBytes, manifestBytes));
});

test('bundled lock nodes require exact direct membership and remain ci-compatible', () => {
  const bundled = structuredClone(lock);
  bundled.packages['node_modules/@example/package'].bundleDependencies = ['bundled-leaf'];
  bundled.packages['node_modules/@example/package'].dependencies = {'bundled-leaf': '^1.0.0'};
  bundled.packages['node_modules/@example/package/node_modules/bundled-leaf'] = {version: '1.0.0', inBundle: true};
  const encoded = Buffer.from(JSON.stringify(bundled));
  reviewedProject(configuration(env, 'ci'), manifestBytes, encoded);
  installationSummary(configuration(env, 'install'), summary, installedBytes, encoded, manifestBytes);
  const unrelated = structuredClone(bundled);
  unrelated.packages['node_modules/@example/package/node_modules/unrelated'] = {version: '1.0.0', inBundle: true};
  assert.throws(() => reviewedProject(configuration(env, 'ci'), manifestBytes, Buffer.from(JSON.stringify(unrelated))));
  const inherited = structuredClone(bundled);
  inherited.packages['node_modules/@example/package/node_modules/bundled-leaf/node_modules/other'] = {version: '1.0.0', inBundle: true};
  assert.throws(() => reviewedProject(configuration(env, 'ci'), manifestBytes, Buffer.from(JSON.stringify(inherited))));
  delete bundled.packages['node_modules/@example/package'].bundleDependencies;
  assert.throws(() => reviewedProject(configuration(env, 'ci'), manifestBytes, Buffer.from(JSON.stringify(bundled))));
  assert.throws(() => installationSummary(configuration(env, 'install'), summary, installedBytes,
    Buffer.from(JSON.stringify(bundled)), manifestBytes));
});

test('one stock installation call uses output directory, validates files and preserves ci lock', async () => {
  for (const operation of ['install', 'ci']) {
    let calls = 0;
    const result = await perform(configuration(env, operation), paths, {
      node: '/node', env: {}, pacote: {manifest() { assert.fail('no pacote override'); }},
      readFile(file) {
        if (file === paths.project + '/package.json') return manifestBytes;
        if (file === paths.project + '/package-lock.json') return lockBytes;
        assert.equal(file, paths.project + '/node_modules/@example/package/package.json'); return installedBytes;
      },
      spawn(node, args, options) {
        calls++; assert.equal(options.cwd, paths.project); assert.equal(options.timeout, 55000);
        return {status: 0, signal: null, stderr: '', stdout: JSON.stringify(summary)};
      },
    });
    assert.equal(calls, 1); assert.equal(result.installed, true); assert.equal(result.operation, operation);
  }
  let reads = 0;
  await assert.rejects(perform(configuration(env, 'ci'), paths, {node: '/node', env: {},
    readFile(file) {
      if (file.endsWith('/package.json')) return manifestBytes;
      return ++reads === 1 ? lockBytes : Buffer.concat([lockBytes, Buffer.from('\n')]);
    }, spawn() { return {status: 0, signal: null, stderr: '', stdout: JSON.stringify(summary)}; }}));
});

test('fresh output contains only reviewed inputs; original project and existing output are not modified', () => {
  const owned = mkdtempSync(join(tmpdir(), 'catchplate-npm-copy-test-'));
  try {
    const project = join(owned, 'input'), output = join(owned, 'output');
    mkdirSync(project, {mode: 0o700});
    writeFileSync(join(project, 'package.json'), manifestBytes);
    writeFileSync(join(project, 'package-lock.json'), lockBytes);
    writeFileSync(join(project, '.npmrc'), 'registry=https://ignored.example.invalid/\n');
    mkdirSync(join(project, 'node_modules'), {mode: 0o700});
    writeFileSync(join(project, 'node_modules', 'keep'), 'original');
    const config = configuration({...env, CATCHPLATE_NPM_PROJECT: project, CATCHPLATE_NPM_OUTPUT: output}, 'ci');
    createInstallationProject(config);
    assert.deepEqual(readdirSync(output).sort(), ['package-lock.json', 'package.json']);
    assert.equal(statSync(output).mode & 0o777, 0o700);
    assert.deepEqual(readFileSync(join(output, 'package.json')), manifestBytes);
    assert.deepEqual(readFileSync(join(output, 'package-lock.json')), lockBytes);
    assert.throws(() => createInstallationProject(config));
    assert.equal(readFileSync(join(project, 'node_modules', 'keep'), 'utf8'), 'original');
    assert.equal(readFileSync(join(project, '.npmrc'), 'utf8'), 'registry=https://ignored.example.invalid/\n');
  } finally { rmSync(owned, {recursive: true, force: false}); }
});

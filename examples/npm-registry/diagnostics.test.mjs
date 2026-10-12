// Pure/inert dependency tests: no npm, subprocess, network or file access.
import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { sanitizeDiagnostic, caughtDiagnostic, processDiagnostic, workerDiagnostic } from './diagnostics.mjs';
import { perform } from './worker.mjs';
import { invokeWorker } from './client.mjs';

const CANARY = 'private_token_path_provider_error_canary';
const EMPTY = { schema: 'serverware.npmExampleDiagnostic/v1', launcherStage: null, workerStage: null,
  processRole: null, exitCode: null, signal: null, systemCode: null, npmCode: null };
const config = { operation: 'ci', packageName: 'fixture-package', version: '1.0.0' };
const paths = { root: '/task', project: '/output', npmCli: '/npm/cli', npmrc: '/task/user', globalrc: '/task/global' };
const manifest = Buffer.from(JSON.stringify({name: 'fixture-consumer', version: '1.0.0', private: true,
  dependencies: {'fixture-package': '1.0.0'}}));
const lock = Buffer.from(JSON.stringify({name: 'fixture-consumer', version: '1.0.0', lockfileVersion: 3, packages: {
  '': {dependencies: {'fixture-package': '1.0.0'}},
  'node_modules/fixture-package': {version: '1.0.0', resolved: 'https://registry.npmjs.org/fixture-package/-/fixture-package-1.0.0.tgz',
    integrity: 'sha512-' + 'A'.repeat(86) + '=='},
}}));
const npmSummary = {added: 1, audited: 2, audit: {dependencies: {total: 1},
  vulnerabilities: {info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0}}};
const success = {status: 0, signal: null, stderr: '', stdout: JSON.stringify(npmSummary)};
function dependencies(patch = {}) {
  return {node: '/node', env: {}, spawn: () => success,
    readFile(path) {
      if (path === '/output/package.json') return manifest;
      if (path === '/output/package-lock.json') return lock;
      assert.equal(path, '/output/node_modules/fixture-package/package.json');
      return Buffer.from('{"name":"fixture-package","version":"1.0.0"}');
    }, ...patch};
}
async function observeFailure(patch) {
  let observed = {...EMPTY};
  await assert.rejects(perform(config, paths, dependencies({...patch,
    observe(update) { observed = sanitizeDiagnostic({...observed, ...update}); },
  })));
  assert.ok(!JSON.stringify(observed).includes(CANARY));
  return observed;
}

test('whole diagnostic has closed keys, enums, numeric bounds and no reflected canary', () => {
  assert.deepEqual(sanitizeDiagnostic(), EMPTY);
  for (const value of [null, [], false, CANARY]) assert.deepEqual(sanitizeDiagnostic(value), EMPTY);
  const source = Object.fromEntries(Object.keys(EMPTY).map(key => [key, CANARY]));
  const safe = sanitizeDiagnostic({...source, message: CANARY, path: CANARY, argv: [CANARY], stderr: CANARY});
  assert.deepEqual(Object.keys(safe), Object.keys(EMPTY));
  assert.equal(safe.schema, EMPTY.schema);
  for (const key of Object.keys(EMPTY).slice(1)) assert.equal(safe[key], 'other');
  assert.ok(!JSON.stringify(safe).includes(CANARY));
  for (const exitCode of [false, true, -1, 256, 1.5, '1', {}, Infinity])
    assert.equal(sanitizeDiagnostic({exitCode}).exitCode, 'other');
  for (const exitCode of [0, 1, 70, 255]) assert.equal(sanitizeDiagnostic({exitCode}).exitCode, exitCode);
});

test('known stages and codes survive; caught messages never do', () => {
  const safe = sanitizeDiagnostic({launcherStage: 'worker_process', workerStage: 'npm_process',
    processRole: 'npm', exitCode: 1, signal: 'SIGKILL', systemCode: 'EAGAIN', npmCode: 'EUSAGE'});
  assert.equal(safe.workerStage, 'npm_process'); assert.equal(safe.systemCode, 'EAGAIN');
  assert.equal(safe.npmCode, 'EUSAGE');
  assert.deepEqual(caughtDiagnostic(safe, new Error(CANARY)), safe);
  assert.equal(caughtDiagnostic(EMPTY, {code: CANARY, message: CANARY, path: CANARY}).systemCode, 'other');
  assert.equal(caughtDiagnostic(EMPTY, {code: 'ENOENT', message: CANARY}).systemCode, 'ENOENT');
});

test('npm JSON error code is classified, not its arbitrary error text', () => {
  const result = {status: 1, signal: null, stderr: CANARY,
    stdout: JSON.stringify({error: {code: 'EUSAGE', summary: CANARY, detail: CANARY}})};
  assert.deepEqual(processDiagnostic('npm', result), {processRole: 'npm', exitCode: 1,
    signal: null, systemCode: null, npmCode: 'EUSAGE'});
  for (const stdout of [CANARY, JSON.stringify({error: {code: CANARY}}), 'x'.repeat(2 * 1024 * 1024 + 1)]) {
    const safe = processDiagnostic('npm', {...result, stdout});
    assert.ok(!JSON.stringify(safe).includes(CANARY));
    assert.ok(safe.npmCode === null || safe.npmCode === 'other');
  }
  assert.equal(processDiagnostic('worker', result).npmCode, null);
  assert.equal(processDiagnostic('npm', {...result, status: 0, stderr: ''}).npmCode, null);
});

test('worker JSON handoff is bounded, schema-specific and independently sanitized', () => {
  for (const value of [CANARY, '{}', JSON.stringify({ok: false, diagnostic: {schema: CANARY}}),
    'x'.repeat(16385)]) assert.equal(workerDiagnostic(value), null);
  const safe = workerDiagnostic(JSON.stringify({ok: false, error: CANARY, path: CANARY,
    diagnostic: {...EMPTY, launcherStage: CANARY, workerStage: 'installation_input', systemCode: CANARY,
      message: CANARY}}));
  assert.equal(safe.workerStage, 'installation_input'); assert.equal(safe.launcherStage, null);
  assert.equal(safe.systemCode, 'other'); assert.ok(!JSON.stringify(safe).includes(CANARY));
});

test('ci missing input is observed before npm and no error text is retained', async () => {
  const safe = await observeFailure({readFile() { throw new Error(CANARY); },
    spawn() { assert.fail('must not launch npm'); }});
  assert.equal(safe.workerStage, 'installation_input'); assert.equal(safe.processRole, null);
});

test('ci nonzero npm exit remains refused with closed npm process diagnostic', async () => {
  const safe = await observeFailure({spawn() { return {status: 1, signal: null, stderr: CANARY,
    stdout: JSON.stringify({error: {code: 'EUSAGE', detail: CANARY}})}; }});
  assert.equal(safe.workerStage, 'npm_process'); assert.equal(safe.exitCode, 1);
  assert.equal(safe.npmCode, 'EUSAGE');
});

test('ci successful process with stderr still fails unchanged process guard', async () => {
  const safe = await observeFailure({spawn: () => ({...success, stderr: CANARY})});
  assert.equal(safe.workerStage, 'npm_process'); assert.equal(safe.exitCode, 0);
});

test('ci malformed npm JSON and changed lock have distinct refused stages', async () => {
  assert.equal((await observeFailure({spawn: () => ({...success, stdout: CANARY})})).workerStage, 'npm_json');
  let locks = 0;
  const base = dependencies();
  const safe = await observeFailure({readFile(path) {
    if (path === '/output/package-lock.json' && ++locks === 2) return Buffer.concat([lock, Buffer.from('\n')]);
    return base.readFile(path);
  }});
  assert.equal(safe.workerStage, 'installation_readback');
});

test('ci absent audit summary remains refused after process and file checks', async () => {
  const safe = await observeFailure({spawn: () => ({...success, stdout: '{"added":1,"audited":0}'})});
  assert.equal(safe.workerStage, 'installation_summary'); assert.equal(safe.exitCode, 0);
});

test('successful perform has no diagnostic field and preserves original success fields', async () => {
  const observed = [];
  const result = await perform(config, paths, dependencies({observe: value => observed.push(value)}));
  assert.equal(result.ok, true); assert.equal(result.operation, 'ci');
  assert.equal(result.defaultAuditReportedSuccess, true); assert.equal(Object.hasOwn(result, 'diagnostic'), false);
  assert.equal(observed.at(-1).workerStage, 'installation_summary');
});

test('worker launch error is classified through inert child without reflecting error', async () => {
  const child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  const observed = [];
  const pending = invokeWorker('/node', [], {}, () => child, 1000, value => observed.push(value));
  child.emit('error', Object.assign(new Error(CANARY), {code: 'EAGAIN', path: CANARY}));
  await assert.rejects(pending, {message: 'npm worker unavailable'});
  assert.deepEqual(observed, [{processRole: 'worker', exitCode: null, signal: null, systemCode: 'EAGAIN', npmCode: null}]);
  child.stdout.destroy(); child.stderr.destroy();
});

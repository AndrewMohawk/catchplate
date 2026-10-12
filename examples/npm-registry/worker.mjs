// Internal child: launched only after extra CA trust and a clean environment exist.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configuration, requireValue, pacoteOptions, npmArguments, reviewedTarball,
  reviewedManifest, metadataSummary, publishSummary, failure } from './core.mjs';
import { isInstallation, reviewedProject, installationSummary } from './core.mjs';
import { sanitizeDiagnostic, caughtDiagnostic, processDiagnostic } from './diagnostics.mjs';

export async function perform(config, paths, { pacote, spawn, node, env, readFile, observe = () => {} }) {
  if (config.operation === 'manifest') {
    observe({ workerStage: 'manifest' });
    return metadataSummary(config, await pacote.manifest(config.packageName + '@' + config.version,
      pacoteOptions(config, paths.cache)));
  }
  let bytes;
  let initialLock, projectManifest;
  if (isInstallation(config.operation)) {
    observe({ workerStage: 'installation_input' });
    initialLock = config.operation === 'ci' ? readFile(join(paths.project, 'package-lock.json')) : null;
    projectManifest = readFile(join(paths.project, 'package.json'));
    reviewedProject(config, projectManifest, initialLock);
  }
  if (config.operation === 'publish') {
    observe({ workerStage: 'publication_input' });
    bytes = reviewedTarball(config, readFile(paths.tarball));
    // Stock local-file inspection only, no URL, scripts or dependency installation.
    // pacote may unpack this reviewed archive into the private cache to read its manifest.
    reviewedManifest(config, await pacote.manifest(paths.tarball,
      { cache: paths.cache, tufCache: paths.cache + '/tuf', offline: true, ignoreScripts: true }));
  }
  observe({ workerStage: 'npm_process', processRole: 'npm' });
  const result = spawn(node, npmArguments(config, paths), { cwd: isInstallation(config.operation) ? paths.project : paths.root, env,
    timeout: isInstallation(config.operation) ? 55000 : 12000,
    killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, encoding: 'utf8' });
  observe(processDiagnostic('npm', result));
  requireValue(!result.error && result.signal === null && result.status === 0 && result.stderr === '');
  observe({ workerStage: 'npm_json' });
  const value = JSON.parse(result.stdout);
  if (isInstallation(config.operation)) {
    observe({ workerStage: 'installation_readback' });
    const lock = readFile(join(paths.project, 'package-lock.json'));
    if (initialLock) requireValue(lock.equals(initialLock));
    requireValue(readFile(join(paths.project, 'package.json')).equals(projectManifest));
    const installedManifest = readFile(join(paths.project, 'node_modules', config.packageName, 'package.json'));
    observe({ workerStage: 'installation_summary' });
    return installationSummary(config, value, installedManifest, lock, projectManifest);
  }
  observe({ workerStage: 'result_summary' });
  return config.operation === 'publish' ? publishSummary(config, value, bytes) : metadataSummary(config, value);
}

async function main() {
  const operation = process.argv[2];
  let timer;
  let diagnostic = sanitizeDiagnostic({ workerStage: 'configuration' });
  const observe = update => { diagnostic = sanitizeDiagnostic({ ...diagnostic, ...update }); };
  try {
    requireValue(process.argv.length === 3 && process.version === 'v25.5.0');
    const config = configuration(process.env, operation);
    observe({ workerStage: 'runtime' });
    const root = process.env.SERVERWARE_NPM_WORK;
    requireValue(typeof root === 'string' && resolve(root) === root && root === process.cwd()
      && process.env.NODE_EXTRA_CA_CERTS === join(root, 'trust.pem'));
    const directory = dirname(fileURLToPath(import.meta.url));
    const load = createRequire(import.meta.url);
    const paths = { root, cache: join(root, 'cache'), tarball: join(root, 'reviewed-package.tgz'),
      npmCli: join(directory, 'node_modules/npm/bin/npm-cli.js'),
      npmrc: join(root, 'user.npmrc'), globalrc: join(root, 'global.npmrc'),
      ...(isInstallation(operation) ? { project: config.output } : {}) };
    timer = setTimeout(() => process.exit(70), isInstallation(operation) ? 60000 : 14000);
    observe({ workerStage: 'dependencies' });
    const result = await perform(config, paths, { pacote: load('pacote'), spawn: spawnSync,
      node: process.execPath, env: process.env, readFile: readFileSync, observe });
    console.log(JSON.stringify(result));
  } catch (error) {
    console.error(JSON.stringify({ ...failure(operation), diagnostic: caughtDiagnostic(diagnostic, error) }));
    process.exitCode = 1;
  } finally { clearTimeout(timer); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();

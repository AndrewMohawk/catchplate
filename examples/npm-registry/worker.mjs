// Internal child: launched only after extra CA trust and a clean environment exist.
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configuration, requireValue, pacoteOptions, npmArguments, reviewedTarball,
  reviewedManifest, metadataSummary, publishSummary, failure } from './core.mjs';

export async function perform(config, paths, { pacote, spawn, node, env, readFile }) {
  if (config.operation === 'manifest') {
    return metadataSummary(config, await pacote.manifest(config.packageName + '@' + config.version,
      pacoteOptions(config, paths.cache)));
  }
  let bytes;
  if (config.operation === 'publish') {
    bytes = reviewedTarball(config, readFile(paths.tarball));
    // Stock local-file inspection only, no URL, scripts or dependency installation.
    // pacote may unpack this reviewed archive into the private cache to read its manifest.
    reviewedManifest(config, await pacote.manifest(paths.tarball,
      { cache: paths.cache, tufCache: paths.cache + '/tuf', offline: true, ignoreScripts: true }));
  }
  const result = spawn(node, npmArguments(config, paths), { cwd: paths.root, env,
    timeout: 12000, killSignal: 'SIGKILL', maxBuffer: 2 * 1024 * 1024, encoding: 'utf8' });
  requireValue(!result.error && result.signal === null && result.status === 0 && result.stderr === '');
  const value = JSON.parse(result.stdout);
  return config.operation === 'publish' ? publishSummary(config, value, bytes) : metadataSummary(config, value);
}

async function main() {
  const operation = process.argv[2];
  let timer;
  try {
    requireValue(process.argv.length === 3 && process.version === 'v25.5.0');
    const config = configuration(process.env, operation);
    const root = process.env.SERVERWARE_NPM_WORK;
    requireValue(typeof root === 'string' && resolve(root) === root && root === process.cwd()
      && process.env.NODE_EXTRA_CA_CERTS === join(root, 'trust.pem'));
    const directory = dirname(fileURLToPath(import.meta.url));
    const load = createRequire(import.meta.url);
    const paths = { root, cache: join(root, 'cache'), tarball: join(root, 'reviewed-package.tgz'),
      npmCli: join(directory, 'node_modules/npm/bin/npm-cli.js'),
      npmrc: join(root, 'user.npmrc'), globalrc: join(root, 'global.npmrc') };
    timer = setTimeout(() => process.exit(70), 14000);
    const result = await perform(config, paths, { pacote: load('pacote'), spawn: spawnSync,
      node: process.execPath, env: process.env, readFile: readFileSync });
    console.log(JSON.stringify(result));
  } catch {
    console.error(JSON.stringify(failure(operation)));
    process.exitCode = 1;
  } finally { clearTimeout(timer); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();

#!/usr/bin/env node
'use strict';
// Select only the existing closed browser diagnostic. No raw logs or fallback
// diagnostics, no application import, and no rerun when evidence is missing.
const fs = require('node:fs');
const path = require('node:path');
const {publicFailureReceipt} = require('./check_operator_guided_browser.cjs');
function need(value) { if (!value) throw new Error('Guided failure selection refused'); }
function ownedDirectory(directory, mode) {
  const info = fs.lstatSync(directory);
  need(fs.realpathSync(directory) === directory && info.isDirectory() && info.uid === process.geteuid() &&
    (info.mode & 0o777) === mode);
}
function main() {
  const root = process.env.GUIDED_EVIDENCE;
  if (root === undefined) return;
  need(path.dirname(root) === '/srv/catchplate-fast/tmp' &&
    /^serverware-guided-evidence\.[A-Za-z0-9]{8}$/.test(path.basename(root)));
  ownedDirectory(root, 0o700);
  const input = path.join(root, 'guided-browser-failure.json');
  let fd;
  try { fd = fs.openSync(input, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK); }
  catch (error) { if (error.code === 'ENOENT') return; throw error; }
  let projected;
  try {
    const before = fs.fstatSync(fd, {bigint: true});
    need(before.isFile() && before.uid === BigInt(process.geteuid()) && before.nlink === 1n &&
      (before.mode & 0o777n) === 0o600n && before.size > 0n && before.size <= 4096n);
    const buffer = Buffer.alloc(4097), length = fs.readSync(fd, buffer, 0, buffer.length, 0);
    const after = fs.fstatSync(fd, {bigint: true}), named = fs.lstatSync(input, {bigint: true});
    need(BigInt(length) === before.size && ['dev', 'ino', 'size', 'mtimeNs', 'ctimeNs'].every(key =>
      before[key] === after[key] && before[key] === named[key]));
    projected = publicFailureReceipt(buffer.subarray(0, length));
  } finally { fs.closeSync(fd); }
  need(typeof process.env.RUNNER_TEMP === 'string' && path.isAbsolute(process.env.RUNNER_TEMP));
  const destination = path.join(process.env.RUNNER_TEMP, 'serverware-guided-public');
  ownedDirectory(destination, 0o700);
  fs.writeFileSync(path.join(destination, 'browser-failure.json'), JSON.stringify(projected) + '\n', {flag: 'wx', mode: 0o600});
}
if (require.main === module) {
  try { main(); } catch (_) { process.stderr.write('Guided failure selection refused; no private details emitted\n'); process.exitCode = 1; }
}

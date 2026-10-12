// Failure-only observations, never approval or a replacement for success checks.
// No exception message, path, argv, provider body or stderr is returned.
export const DIAGNOSTIC_SCHEMA = 'serverware.npmExampleDiagnostic/v1';
const LAUNCHER = new Set(['configuration', 'versions', 'trust', 'publication_input', 'installation_input',
  'runtime_setup', 'worker_process', 'worker_summary', 'installation_summary', 'cleanup', 'other']);
const WORKER = new Set(['configuration', 'runtime', 'dependencies', 'manifest', 'installation_input',
  'publication_input', 'npm_process', 'npm_json', 'installation_readback', 'installation_summary', 'result_summary', 'other']);
const SIGNAL = new Set(['SIGTERM', 'SIGKILL', 'SIGABRT', 'SIGSEGV', 'SIGINT', 'other']);
const SYSTEM = new Set(['ENOENT', 'EACCES', 'EPERM', 'EAGAIN', 'ENOMEM', 'ENOSPC', 'ETIMEDOUT',
  'ENOBUFS', 'EIO', 'EEXIST', 'ENOTDIR', 'other']);
const NPM = new Set(['EUSAGE', 'ECIGLOBAL', 'ENOLOCK', 'ENOENT', 'EACCES', 'EPERM', 'ENOSPC',
  'E400', 'E401', 'E403', 'E404', 'E409', 'E429', 'E500', 'E502', 'E503', 'ETIMEDOUT',
  'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EINTEGRITY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'other']);
const ROLE = new Set(['worker', 'npm', 'other']);
const selected = (value, allowed) => value === null || value === undefined ? null
  : typeof value === 'string' && allowed.has(value) ? value : 'other';

export function sanitizeDiagnostic(value = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) value = {};
  return { schema: DIAGNOSTIC_SCHEMA,
    launcherStage: selected(value.launcherStage, LAUNCHER), workerStage: selected(value.workerStage, WORKER),
    processRole: selected(value.processRole, ROLE),
    exitCode: value.exitCode === null || value.exitCode === undefined ? null
      : Number.isInteger(value.exitCode) && value.exitCode >= 0 && value.exitCode <= 255 ? value.exitCode : 'other',
    signal: selected(value.signal, SIGNAL), systemCode: selected(value.systemCode, SYSTEM), npmCode: selected(value.npmCode, NPM) };
}

export function caughtDiagnostic(current, error) {
  return sanitizeDiagnostic({ ...current, systemCode: current.systemCode ?? error?.code });
}

export function processDiagnostic(role, result) {
  let npmCode = null;
  if (role === 'npm' && (result.error || result.signal !== null || result.status !== 0 || result.stderr !== '')
    && typeof result.stdout === 'string' && Buffer.byteLength(result.stdout) <= 2 * 1024 * 1024) {
    try { npmCode = JSON.parse(result.stdout)?.error?.code ?? null; }
    catch { /* Unparseable output is not reflected into the diagnostic. */ }
  }
  const safe = sanitizeDiagnostic({ processRole: role, exitCode: result.status, signal: result.signal,
    systemCode: result.error?.code, npmCode });
  return { processRole: safe.processRole, exitCode: safe.exitCode, signal: safe.signal,
    systemCode: safe.systemCode, npmCode: safe.npmCode };
}

export function workerDiagnostic(stderr) {
  // The worker's generic failure is untrusted transport input here. Only a
  // bounded JSON diagnostic in our schema is inspected; every field is closed.
  if (typeof stderr !== 'string' || Buffer.byteLength(stderr) > 16384) return null;
  try {
    const value = JSON.parse(stderr);
    if (value?.ok !== false || value?.diagnostic?.schema !== DIAGNOSTIC_SCHEMA) return null;
    const safe = sanitizeDiagnostic(value.diagnostic);
    safe.launcherStage = null;
    return safe;
  } catch { return null; }
}

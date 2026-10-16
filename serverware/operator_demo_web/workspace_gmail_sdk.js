// Presentation only. Callers own the exact saved-rule, loaded-policy and token
// gates. No provider access, token discovery, grant change or executable download.
function gmailSdkLanguage(language = 'go') {
  const profiles = {
    go: {label: 'Go', directory: 'examples/google-gmail-go', entrypoint: './gmail-example', arguments: [],
      preparation: 'Build the reviewed Go example first, as described in its README. Use its already-built ./gmail-example.'},
    node: {label: 'Node.js', directory: 'examples/google-gmail-node', entrypoint: 'node', arguments: ['client.mjs'],
      preparation: 'Use Node.js 22.19 or newer (isolated verification used 25.5.0). Before supplying a token, run npm ci --ignore-scripts --no-audit --no-fund in this project, using its checked-in lockfile.'},
    python: {label: 'Python', directory: 'examples/google-gmail-python', entrypoint: '.venv/bin/python', arguments: ['-I', '-B', 'gmail.py'],
      preparation: 'Use CPython 3.12 (isolated verification used 3.12.3). Before supplying a token, create .venv and install requirements.txt there with --only-binary=:all:, then run .venv/bin/python -m pip check. Follow the project README.'},
  };
  if (typeof language !== 'string' || !Object.hasOwn(profiles, language))
    throw new Error('Choose a supported Gmail SDK language');
  return profiles[language];
}
function gmailSdkAgeDays(policy) {
  if (policy === undefined) return null; // Existing standalone connection recipe.
  if (policy && typeof policy === 'object' && !Array.isArray(policy)) {
    if (Object.hasOwn(policy, 'mode') && policy.mode === 'unrestricted' && Object.keys(policy).length === 1) return null;
    if (Object.hasOwn(policy, 'mode') && Object.hasOwn(policy, 'max_age_days') &&
        policy.mode === 'recent_internal_date_v1' && Object.keys(policy).length === 2 &&
        Number.isSafeInteger(policy.max_age_days) && policy.max_age_days >= 1 && policy.max_age_days <= 3650)
      return policy.max_age_days;
  }
  throw new Error('Choose all mail or a whole-number age limit from 1 to 3650 days');
}
function gmailSdkPublicConfiguration({proxyUrl, applicationId, accessRuleId, tokenExpiresAtEpochMs,
    caPath = './serverware-ca.pem', proxyCaPath = '', nowEpochMs = Date.now(), language = 'go', agePolicy}) {
  gmailSdkAgeDays(agePolicy);
  const profile = gmailSdkLanguage(language);
  const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const match = typeof proxyUrl === 'string' && proxyUrl.match(/^https:\/\/([a-z0-9.-]+)(?::([0-9]{1,5}))?\/?$/);
  if (!match || match[1].length > 253 || !match[1].includes('.') || /^[0-9.]+$/.test(match[1]) ||
      match[1] === 'gmail.googleapis.com' || match[1].endsWith('.local') || match[1].endsWith('.localhost') ||
      match[1].split('.').some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
      match[2] !== undefined && !(Number(match[2]) >= 1 && Number(match[2]) <= 65535) ||
      typeof applicationId !== 'string' || !uuid.test(applicationId) ||
      typeof accessRuleId !== 'string' || !uuid.test(accessRuleId) ||
      !Number.isSafeInteger(nowEpochMs) || nowEpochMs <= 0 ||
      !Number.isSafeInteger(tokenExpiresAtEpochMs) || tokenExpiresAtEpochMs <= nowEpochMs)
    throw new Error('A current saved Gmail SDK application and HTTPS proxy are required');
  for (const value of [caPath, proxyCaPath])
    if (typeof value !== 'string' || value.length > 512 || /[\u0000-\u001f\u007f]/.test(value))
      throw new Error('CA file paths must be bounded printable text');
  if (!caPath) throw new Error('The downloaded Serverware CA file is required');
  const environment = {LANG: 'C.UTF-8', SERVERWARE_PROXY_URL: proxyUrl,
    SERVERWARE_APP_ID: applicationId, SERVERWARE_CA_FILE: caPath};
  if (proxyCaPath) environment.SERVERWARE_PROXY_CA_FILE = proxyCaPath;
  // Preserve the existing default Go download exactly. New interpreted launch
  // profiles explicitly describe their argument vector and CA-path preparation.
  return {schema: language === 'go' ? 'serverware.gmailSdkClient/v1' : 'serverware.gmailSdkClient/v2',
    ...(language === 'go' ? {} : {language, arguments: [...profile.arguments], resolve_ca_paths: true,
      resolve_executable_from_path: language === 'node'}),
    example_directory: profile.directory, entrypoint: profile.entrypoint,
    clear_environment: true, environment,
    token_expires_at_epoch_ms: tokenExpiresAtEpochMs, access_rule_id: accessRuleId};
}
function gmailSdkShellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}
function gmailSdkFileCommand(language = 'go') {
  const profile = gmailSdkLanguage(language);
  return [profile.entrypoint, ...profile.arguments, '--config', './serverware-client.private.json'].join(' ');
}
function buildGmailSdkClientRecipe(options) {
  const config = gmailSdkPublicConfiguration(options);
  const language = options.language === undefined ? 'go' : options.language;
  const profile = gmailSdkLanguage(language);
  const child = ['set -eu', 'IFS= read -r SERVERWARE_PROXY_TOKEN', 'exec </dev/null',
    'unset PWD OLDPWD SHLVL _', 'export SERVERWARE_PROXY_TOKEN'];
  for (const [key, value] of Object.entries(config.environment))
    if (key !== 'LANG') child.push('export ' + key + '=' + gmailSdkShellQuote(value));
  const ageDays = gmailSdkAgeDays(options.agePolicy);
  if (ageDays !== null) child.push('export SERVERWARE_GMAIL_MAX_AGE_DAYS=' + gmailSdkShellQuote(String(ageDays)));
  if (language !== 'go') {
    for (const key of ['SERVERWARE_CA_FILE', 'SERVERWARE_PROXY_CA_FILE'])
      if (Object.hasOwn(config.environment, key))
        child.push(key + '="$(/usr/bin/realpath -e -- "$' + key + '")"',
          '[ -f "$' + key + '" ]', 'export ' + key);
  }
  child.push(language === 'go' ? 'exec ./gmail-example' : language === 'node' ?
    'exec "$1" client.mjs' : 'exec .venv/bin/python -I -B gmail.py');
  return [
    language === 'go' ? '# Gmail SDK job (Bash): run from examples/google-gmail-go with the reviewed ./gmail-example already built.' :
      '# Gmail SDK job (Bash): run from ' + profile.directory + ' after preparing its pinned dependencies.',
    ...(language === 'go' ? [] : ['# ' + profile.preparation,
      '# CA paths are resolved relative to this project before launch; no ambient proxy, Google credentials or TLS overrides are inherited.']),
    '# Prepare dependencies/build before supplying the app token. This recipe does not download or build anything.',
    '# Set SERVERWARE_PROXY_TOKEN privately first. Never use a Google token. Both TLS checks remain enabled.',
    '# ' + config.schema,
    '# access_rule_id: ' + config.access_rule_id,
    '# token_expires_at_epoch_ms: ' + config.token_expires_at_epoch_ms,
    '(',
    '  set +x',
    '  set -eu',
    '  case "${SERVERWARE_PROXY_TOKEN-}" in',
    "    ''|*[!A-Za-z0-9_-]*) printf '%s\\n' 'Set the issued Serverware application token privately' >&2; exit 1 ;;",
    '  esac',
    '  [ "${#SERVERWARE_PROXY_TOKEN}" -eq 43 ] || { printf \'%s\\n\' \'Set the issued Serverware application token privately\' >&2; exit 1; }',
    ...(language === 'node' ? ['  SERVERWARE_GMAIL_NODE="$(type -P node)"',
      '  case "$SERVERWARE_GMAIL_NODE" in /*) [ -x "$SERVERWARE_GMAIL_NODE" ] ;; *) exit 1 ;; esac'] : []),
    '  printf \'%s\\n\' "$SERVERWARE_PROXY_TOKEN" |',
    '    /usr/bin/env -i LANG=C.UTF-8 /bin/sh -c ' + gmailSdkShellQuote(child.join('\n')) +
      (language === 'node' ? ' gmail-sdk "$SERVERWARE_GMAIL_NODE"' : ''),
    ')',
  ].join('\n');
}
function gmailSdkClientConfiguration(options, token) {
  // This is only for the explicitly requested private JSON download. The public
  // recipe never accepts a token argument or embeds a token in text/argv/URLs.
  if (typeof token !== 'string' || !/^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/.test(token))
    throw new Error('The matching issued application token is required for private SDK configuration');
  const config = gmailSdkPublicConfiguration(options);
  config.environment.SERVERWARE_PROXY_TOKEN = token;
  return config;
}

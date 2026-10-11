// Presentation only. Callers own the exact saved-rule, loaded-policy and token
// gates. No provider access, token discovery, grant change or executable download.
function gmailSdkPublicConfiguration({proxyUrl, applicationId, accessRuleId, tokenExpiresAtEpochMs,
    caPath = './serverware-ca.pem', proxyCaPath = '', nowEpochMs = Date.now()}) {
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
  return {schema: 'serverware.gmailSdkClient/v1', example_directory: 'examples/google-gmail-go',
    entrypoint: './gmail-example', clear_environment: true, environment,
    token_expires_at_epoch_ms: tokenExpiresAtEpochMs, access_rule_id: accessRuleId};
}
function gmailSdkShellQuote(value) {
  return "'" + value.replaceAll("'", "'\\''") + "'";
}
function buildGmailSdkClientRecipe(options) {
  const config = gmailSdkPublicConfiguration(options);
  const child = ['set -eu', 'IFS= read -r SERVERWARE_PROXY_TOKEN', 'exec </dev/null',
    'unset PWD OLDPWD SHLVL _', 'export SERVERWARE_PROXY_TOKEN'];
  for (const [key, value] of Object.entries(config.environment))
    if (key !== 'LANG') child.push('export ' + key + '=' + gmailSdkShellQuote(value));
  child.push('exec ./gmail-example');
  return [
    '# Gmail SDK job (Bash): run from examples/google-gmail-go with the reviewed ./gmail-example already built.',
    '# Prepare dependencies/build before supplying the app token. This recipe does not download or build anything.',
    '# Set SERVERWARE_PROXY_TOKEN privately first. Never use a Google token. Both TLS checks remain enabled.',
    '# serverware.gmailSdkClient/v1',
    '# access_rule_id: ' + config.access_rule_id,
    '# token_expires_at_epoch_ms: ' + config.token_expires_at_epoch_ms,
    '(',
    '  set +x',
    '  set -eu',
    '  case "${SERVERWARE_PROXY_TOKEN-}" in',
    "    ''|*[!A-Za-z0-9_-]*) printf '%s\\n' 'Set the issued Serverware application token privately' >&2; exit 1 ;;",
    '  esac',
    '  [ "${#SERVERWARE_PROXY_TOKEN}" -eq 43 ] || { printf \'%s\\n\' \'Set the issued Serverware application token privately\' >&2; exit 1; }',
    '  printf \'%s\\n\' "$SERVERWARE_PROXY_TOKEN" |',
    '    /usr/bin/env -i LANG=C.UTF-8 /bin/sh -c ' + gmailSdkShellQuote(child.join('\n')),
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

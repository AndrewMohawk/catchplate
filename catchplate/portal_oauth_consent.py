"""Explicit enrolled consent UI; browser state is never enrollment authority."""


def enrolled_oauth_profile() -> str:
    try:
        from catchplate import control_plane_oauth_exchange
        return "enrolled-new-credential-v1" if control_plane_oauth_exchange.selected() else "development"
    except Exception:
        return "unavailable"


OAUTH_CONSENT_HTML = r"""
          <div id="oauth-consent-controls" hidden>
            <p id="oauth-consent-hint" class="hint">Enrolled credentials require an active OIDC credential-owner cookie and a fresh hardware passkey. Clear an entered bearer credential yourself. The selected provider determines the available consent workflow.</p>
            <button id="oauth-consent-show-auth" type="button" class="secondary">Show operator credential field</button>
            <button id="oauth-consent-start" type="button" disabled>Fresh passkey + open provider once</button>
            <button id="oauth-consent-discard" type="button" class="secondary">Discard prepared consent</button>
            <p id="oauth-consent-status" class="hint" role="status" aria-live="polite">No consent prepared. No automatic restart or retry.</p>
          </div>
"""


OAUTH_CONSENT_SCRIPT = r"""
    const oauthConsentSchema = 'catchplate.oauthExchangeConsentOptions/v1';
    let oauthConsentPending = null, oauthConsentBusy = false, oauthConsentBlocked = false;
    let oauthConsentEpoch = 0, oauthConsentController = null, oauthConsentSent = false;
    let oauthConsentContext = null, oauthConsentForm = null;
    function oauthConsentNeed(ok) { if (!ok) throw new Error('Consent is blocked or changed; no automatic retry.'); }
    const oauthConsentClosed = (value, fields) => value !== null && typeof value === 'object'
      && !Array.isArray(value) && !(value instanceof OAuthConsentNumber)
      && Object.keys(value).length === fields.length && fields.every(key => Object.hasOwn(value, key));
    const oauthConsentDigest = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
    const oauthConsentText = (value, bound) => typeof value === 'string' && value.length > 0
      && new TextEncoder().encode(value).byteLength <= bound && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
    class OAuthConsentNumber { constructor(raw) { this.raw = raw; Object.freeze(this); } }
    function oauthConsentInteger(value) {
      oauthConsentNeed(value instanceof OAuthConsentNumber && /^(0|[1-9][0-9]*)$/.test(value.raw));
      return BigInt(value.raw);
    }
    // Keep numeric tokens and the exact top-level request span. Epoch ns never
    // pass through Number, JSON.stringify, storage, logs or rendered review.
    function oauthConsentParse(text, maximum = 768 * 1024) {
      oauthConsentNeed(Number.isSafeInteger(maximum) && maximum > 0 && maximum <= 8 * 1024 * 1024
        && typeof text === 'string' && new TextEncoder().encode(text).byteLength <= maximum);
      let offset = 0, nodes = 0, requestOriginal = null;
      const white = () => { while (/[\x20\t\r\n]/.test(text[offset] || '\0')) offset++; };
      function string() {
        const start = offset++; oauthConsentNeed(text[start] === '"'); let escaped = false;
        while (offset < text.length) {
          const c = text[offset++];
          if (!escaped && c === '"') return JSON.parse(text.slice(start, offset));
          if (!escaped && c === '\\') escaped = true; else escaped = false;
        }
        oauthConsentNeed(false);
      }
      function value(depth) {
        oauthConsentNeed(depth <= 20 && ++nodes <= 16384); white();
        if (text[offset] === '"') return string();
        const opening = text[offset];
        if (opening === '{' || opening === '[') {
          offset++; white(); const object = opening === '{', result = object ? Object.create(null) : [];
          const end = object ? '}' : ']'; let count = 0;
          if (text[offset] === end) { offset++; return result; }
          for (;;) {
            oauthConsentNeed(++count <= 256); let key = null;
            if (object) {
              key = string(); oauthConsentNeed(key !== '__proto__' && !Object.hasOwn(result, key));
              white(); oauthConsentNeed(text[offset++] === ':'); white();
            }
            const start = offset, item = value(depth + 1);
            if (object) { result[key] = item; if (depth === 0 && key === 'request') requestOriginal = text.slice(start, offset); }
            else result.push(item);
            white(); if (text[offset] === end) { offset++; return result; }
            oauthConsentNeed(text[offset++] === ','); white();
          }
        }
        const match = /^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(offset));
        oauthConsentNeed(match && match[0].length <= 128); offset += match[0].length;
        return ['null', 'true', 'false'].includes(match[0]) ? JSON.parse(match[0]) : new OAuthConsentNumber(match[0]);
      }
      const parsed = value(0); white(); oauthConsentNeed(offset === text.length);
      return {value: parsed, requestOriginal};
    }
    function oauthConsentCanonical(value) {
      if (value instanceof OAuthConsentNumber) return value.raw;
      if (Array.isArray(value)) return '[' + value.map(oauthConsentCanonical).join(',') + ']';
      if (value && typeof value === 'object') {
        const compare = (a, b) => {
          const x = Array.from(a, c => c.codePointAt(0)), y = Array.from(b, c => c.codePointAt(0));
          for (let i = 0; i < Math.min(x.length, y.length); i++) if (x[i] !== y[i]) return x[i] - y[i];
          return x.length - y.length;
        };
        return '{' + Object.keys(value).sort(compare).map(key => oauthConsentCanonical(key) + ':' + oauthConsentCanonical(value[key])).join(',') + '}';
      }
      return JSON.stringify(value).replace(/[\u007f-\uffff]/g, c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
    }
    function oauthConsentSame(a, b) {
      if (a instanceof OAuthConsentNumber || b instanceof OAuthConsentNumber) {
        if (!(a instanceof OAuthConsentNumber && b instanceof OAuthConsentNumber)) return false;
        if (/^-?[0-9]+$/.test(a.raw) && /^-?[0-9]+$/.test(b.raw)) return BigInt(a.raw) === BigInt(b.raw);
        return Number.isFinite(Number(a.raw)) && Number(a.raw) === Number(b.raw);
      }
      if (a && b && typeof a === 'object' && typeof b === 'object') return Array.isArray(a) === Array.isArray(b)
        && Object.keys(a).length === Object.keys(b).length && Object.keys(a).every(k => Object.hasOwn(b, k) && oauthConsentSame(a[k], b[k]));
      return a === b;
    }
    function oauthConsentFormPin() {
      return JSON.stringify([$('oauth-provider').value, $('oauth-credential-name').value, $('oauth-scopes').value,
        $('oauth-metadata').value, state.oauthSetupSessionId, state.oauthProviders]);
    }
    function oauthConsentLegacySelected() {
      const provider = (state.oauthProviders || []).find(p => p.id === $('oauth-provider').value);
      return provider?.configured === true && !Object.hasOwn(provider, 'consentProfile');
    }
    function oauthConsentActor() {
      const a = state.authStatus;
      oauthConsentNeed(enrolledOAuthProfile === 'enrolled-new-credential-v1' && !adminToken() && !oidcSessionStatusUnknown
        && window.isSecureContext && window.top === window && a?.authenticated === true && a.authMethod === 'oidc-session'
        && a.sessionState === 'active' && a.webauthnRequired === false && oauthConsentText(a.userId, 4096)
        && a.userId.startsWith('oidc:') && Array.isArray(a.roles) && a.roles.includes('credential_owner')
        && (!state.oauthSetupSessionId || nativeOAuthSetupSelected()));
      return a.userId;
    }
    function oauthConsentMessage(text, failed = false) {
      $('oauth-consent-status').textContent = text; $('oauth-consent-status').setAttribute('role', failed ? 'alert' : 'status');
    }
    function oauthConsentInvalidate(message) {
      oauthConsentEpoch++; oauthConsentController?.abort(); oauthConsentPending = null;
      if (oauthConsentSent) oauthConsentBlocked = true;
      oauthConsentContext = sessionActivationAuthScope(); oauthConsentForm = oauthConsentFormPin();
      oauthConsentMessage(message + (oauthConsentBlocked ? ' A sent operation is not retryable from this page.' : ' Prepare again only by an explicit click.'), true);
    }
    function renderOAuthConsent() {
      if (!$('oauth-consent-controls')) return;
      $('oauth-consent-controls').hidden = enrolledOAuthProfile === 'development';
      if (enrolledOAuthProfile === 'development') return;
      if (oauthConsentContext !== null && (oauthConsentContext !== sessionActivationAuthScope() || oauthConsentForm !== oauthConsentFormPin()))
        oauthConsentInvalidate('Actor, roles, trust, policy, provider or form changed; prepared consent discarded.');
      oauthConsentContext = sessionActivationAuthScope(); oauthConsentForm = oauthConsentFormPin();
      if (oauthConsentPending && (Date.now() >= oauthConsentPending.expires || performance.now() >= oauthConsentPending.until))
        oauthConsentInvalidate('Original consent window expired; no allowance was renewed.');
      const native = nativeOAuthSelected(), setup = nativeOAuthSetupSelected(), legacy = oauthConsentLegacySelected();
      $('oauth-consent-hint').textContent = native
        ? (setup ? 'Controlled Setup uses the native preparation and account-review controls below. Create or inspect the matching draft Setup first; account activation and policy approval remain separate.'
          : 'Native consent keeps provider credentials inside the configured native service. Open preparation, review the returned account and scopes, then authorize with a fresh passkey.')
        : 'Enrolled new credentials require an active OIDC credential-owner cookie and a fresh hardware passkey. This consent profile does not support controlled Setup or reconnect.';
      $('oauth-consent-start').hidden = native || !legacy;
      $('oauth-consent-discard').hidden = native || !legacy;
      $('oauth-consent-status').hidden = native && (!state.oauthSetupSessionId || setup)
        && !adminToken() && enrolledOAuthProfile !== 'unavailable';
      let allowed = false; try { oauthConsentActor();
        allowed = (native || legacy) && (state.oauthProviders || []).some(p => p.id === $('oauth-provider').value && p.configured === true);
      } catch (_) {}
      $('oauth-submit').textContent = 'Prepare enrolled consent options';
      $('oauth-submit').disabled = !allowed || oauthConsentBusy || oauthConsentBlocked || oauthConsentPending !== null;
      $('oauth-consent-start').disabled = !allowed || oauthConsentBusy || oauthConsentBlocked || oauthConsentPending === null;
      $('oauth-consent-discard').disabled = oauthConsentBusy;
      if (enrolledOAuthProfile === 'unavailable') oauthConsentMessage('Cold OAuth ownership is unavailable. No development fallback or request is allowed.', true);
      else if (!native && !legacy) oauthConsentMessage('This provider is not configured for new-credential consent. For reconnect or succession, use the matching credential recovery review below; no other consent flow will be substituted.', true);
      else if (state.oauthSetupSessionId && !setup) oauthConsentMessage('This provider profile does not support controlled Setup. Choose the configured Setup provider; no unrelated credential will be created.', true);
      else if (adminToken()) oauthConsentMessage('Clear the entered bearer credential yourself, then refresh the active OIDC cookie status.', true);
      renderNativeOAuth();
    }
    function oauthConsentBegin() {
      oauthConsentNeed(!oauthConsentBusy && !oauthConsentBlocked);
      const actor = oauthConsentActor(), scope = sessionActivationAuthScope(), form = oauthConsentFormPin(), epoch = oauthConsentEpoch;
      const controller = new AbortController(), until = performance.now() + 30000, expires = Date.now() + 30000;
      oauthConsentBusy = true; oauthConsentController = controller;
      const timer = setTimeout(() => controller.abort(), 30000);
      const current = () => oauthConsentNeed(!controller.signal.aborted && performance.now() < until && Date.now() < expires
        && epoch === oauthConsentEpoch && scope === sessionActivationAuthScope() && form === oauthConsentFormPin() && actor === oauthConsentActor());
      renderOAuthConsent();
      return {actor, current, signal: controller.signal, until, expires, close() {
        clearTimeout(timer); oauthConsentBusy = false; oauthConsentController = null; renderOAuthConsent();
      }};
    }
    async function oauthConsentRead(response, maximum, operation) {
      operation.current(); oauthConsentNeed(response.body && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const declared = response.headers.get('Content-Length');
      oauthConsentNeed(declared === null || /^[0-9]+$/.test(declared) && Number(declared) <= maximum);
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let original = '', length = 0, done = false;
      try {
        for (;;) {
          operation.current(); const chunk = await reader.read(); operation.current();
          if (chunk.done) { done = true; break; }
          length += chunk.value.byteLength; oauthConsentNeed(length <= maximum); original += decoder.decode(chunk.value, {stream: true});
        }
        original += decoder.decode(); return oauthConsentParse(original);
      } finally { if (!done) { try { await reader.cancel(); } catch (_) {} } reader.releaseLock(); original = ''; }
    }
    async function oauthConsentRequest(path, original, operation, contact = null) {
      const get = original === null;
      oauthConsentNeed(get ? ['/api/auth/status', '/api/csrf'].includes(path)
        : ['/api/oauth/consent/options', '/api/oauth/start'].includes(path));
      let csrf = null;
      if (!get) {
        oauthConsentNeed(new TextEncoder().encode(original).byteLength <= 768 * 1024);
        const reply = await oauthConsentRequest('/api/csrf', null, operation), v = reply.value;
        oauthConsentNeed(reply.status === 200 && oauthConsentClosed(v, ['ok', 'token', 'cookie', 'header']) && v.ok === true
          && oauthConsentText(v.token, 1024) && v.cookie === 'catchplate_csrf' && v.header === 'X-Catchplate-CSRF-Token'); csrf = v.token;
      }
      try {
        operation.current(); if (contact) contact();
        const response = await fetch(path, {method: get ? 'GET' : 'POST', credentials: 'same-origin', mode: 'same-origin',
          redirect: 'error', cache: 'no-store', signal: operation.signal,
          headers: get ? {} : {'Content-Type': 'application/json', 'X-Catchplate-CSRF-Token': csrf}, body: original});
        const parsed = await oauthConsentRead(response, get ? 16384 : 768 * 1024, operation);
        return {status: response.status, ...parsed};
      } finally { csrf = null; original = null; }
    }
    async function oauthConsentCookie(operation) {
      const reply = await oauthConsentRequest('/api/auth/status', null, operation), a = reply.value;
      oauthConsentNeed(reply.status === 200 && oauthConsentClosed(a, ['authenticated', 'userId', 'roles', 'authMethod',
        'sessionState', 'webauthnRequired', 'oidcBrowserLoginConfigured', 'sessionActivationMode']) && a.authenticated === true
        && a.userId === operation.actor && a.authMethod === 'oidc-session' && a.sessionState === 'active'
        && ['legacy', 'protected', 'unavailable'].includes(a.sessionActivationMode)
        && a.sessionActivationMode === state.authStatus.sessionActivationMode
        && a.webauthnRequired === false && typeof a.oidcBrowserLoginConfigured === 'boolean' && Array.isArray(a.roles)
        && a.roles.length <= 64 && a.roles.every(r => oauthConsentText(r, 128)) && a.roles.includes('credential_owner')
        && new Set(a.roles).size === a.roles.length && JSON.stringify([...a.roles].sort()) === JSON.stringify([...state.authStatus.roles].sort()));
      operation.current();
    }
    async function oauthConsentPrepare() {
      let operation = null;
      try {
        oauthConsentNeed(oauthConsentLegacySelected() && oauthConsentPending === null);
        operation = oauthConsentBegin(); await oauthConsentCookie(operation);
        const provider = (state.oauthProviders || []).find(p => p.id === $('oauth-provider').value);
        oauthConsentNeed(provider?.configured === true && ['google', 'x'].includes(provider.id));
        const metadataOriginal = $('oauth-metadata').value || '{}';
        oauthConsentNeed(new TextEncoder().encode(metadataOriginal).byteLength <= 4096);
        const metadata = oauthConsentParse(metadataOriginal).value;
        oauthConsentNeed(metadata && typeof metadata === 'object' && !Array.isArray(metadata)
          && !(metadata instanceof OAuthConsentNumber) && !Object.hasOwn(metadata, 'oauth_application_owner'));
        const scopes = parseOAuthScopes($('oauth-scopes').value), body = {provider: provider.id,
          credentialName: $('oauth-credential-name').value || null, scopes, metadata};
        const original = oauthConsentCanonical(body); oauthConsentNeed(new TextEncoder().encode(original).byteLength <= 8192);
        const reply = await oauthConsentRequest('/api/oauth/consent/options', original, operation, () => { oauthConsentSent = true; });
        const options = reply.value, request = options?.request;
        oauthConsentNeed(reply.status === 200 && oauthConsentClosed(options, ['publicKey', 'catchplate', 'request'])
          && typeof reply.requestOriginal === 'string' && oauthConsentClosed(request, ['exchangeId', 'stateSha256', 'browserNonceSha256',
            'pkceVerifierSha256', 'stateOriginalSha256', 'stateEnvelope', 'reservedEnvelope', 'providerId', 'redirectUri', 'credentialName',
            'scopes', 'metadata', 'issuedAtEpochNs', 'contactExpiresAtEpochNs', 'retentionExpiresAtEpochNs', 'pendingExpiresAtEpochNs', 'enrollmentSha256', 'limits'])
          && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(request.exchangeId)
          && request.providerId === provider.id && request.redirectUri === provider.redirectUri
          && oauthConsentText(request.credentialName, 256) && (body.credentialName === null || request.credentialName === body.credentialName.trim())
          && Array.isArray(request.scopes) && request.scopes.length >= 1 && request.scopes.length <= 128
          && request.scopes.every(s => oauthConsentText(s, 1024)) && new Set(request.scopes).size === request.scopes.length
          && JSON.stringify(request.scopes) === JSON.stringify(scopes.length ? scopes : provider.defaultScopes));
        for (const key of ['stateSha256', 'browserNonceSha256', 'pkceVerifierSha256', 'stateOriginalSha256', 'enrollmentSha256']) oauthConsentNeed(oauthConsentDigest(request[key]));
        oauthConsentNeed(request.metadata && typeof request.metadata === 'object' && !Array.isArray(request.metadata)
          && Object.keys(request.metadata).length === Object.keys(metadata).length + 1 && Object.hasOwn(request.metadata, 'oauth_application_owner')
          && Object.keys(metadata).every(k => oauthConsentSame(metadata[k], request.metadata[k])));
        for (const envelope of [request.stateEnvelope, request.reservedEnvelope]) {
          oauthConsentNeed(oauthConsentClosed(envelope, ['encrypted_secret', 'encrypted_dek', 'secret_nonce', 'secret_ciphertext', 'secret_kek_id', 'credential_version', 'secret_updated_at'])
            && envelope.encrypted_secret === 'envelope:v2' && oauthConsentInteger(envelope.credential_version) === 1n
            && new TextEncoder().encode(oauthConsentCanonical(envelope)).byteLength <= 256 * 1024);
          for (const key of ['encrypted_dek', 'secret_nonce', 'secret_ciphertext', 'secret_kek_id', 'secret_updated_at']) oauthConsentNeed(oauthConsentText(envelope[key], 256 * 1024));
        }
        const [issued, contact, retention, pending] = ['issuedAtEpochNs', 'contactExpiresAtEpochNs', 'retentionExpiresAtEpochNs', 'pendingExpiresAtEpochNs'].map(k => oauthConsentInteger(request[k]));
        oauthConsentNeed(issued > 0n && issued < contact && contact <= issued + 600000000000n && contact <= retention
          && retention <= contact + 600000000000n && retention <= pending && pending <= contact + 3600000000000n
          && pending <= 9223372036854775807n && oauthConsentClosed(request.limits, ['pendingCapacity', 'revocationCapacity'])
          && oauthConsentInteger(request.limits.pendingCapacity) >= 1n && oauthConsentInteger(request.limits.pendingCapacity) <= 64n
          && oauthConsentInteger(request.limits.revocationCapacity) === 64n);
        const a = options.catchplate, key = options.publicKey;
        oauthConsentNeed(oauthConsentClosed(a, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && a.schema === oauthConsentSchema && a.operation === 'oauth.exchange.prepare' && oauthConsentDigest(a.operationId)
          && oauthConsentDigest(a.challengeId) && oauthConsentText(a.credentialRecordId, 256) && oauthConsentDigest(a.payloadDigest)
          && a.payloadDigest === await workloadIssuanceHash(new TextEncoder().encode(oauthConsentCanonical(request)))
          && oauthConsentText(a.expiresAt, 128) && Number.isFinite(Date.parse(a.expiresAt)));
        oauthConsentNeed(oauthConsentClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          && oauthConsentText(key.rpId, 253) && (location.hostname === key.rpId || location.hostname.endsWith('.' + key.rpId))
          && oauthConsentInteger(key.timeout) === 30000n && key.userVerification === 'required'
          && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
          && oauthConsentClosed(key.allowCredentials[0], ['type', 'id']) && key.allowCredentials[0].type === 'public-key');
        workloadIssuanceBase64(key.challenge, 4096); workloadIssuanceBase64(key.allowCredentials[0].id, 3072);
        const expiryNs = issued + 30000000000n < contact ? issued + 30000000000n : contact;
        const expires = Math.min(Number(expiryNs / 1000000n), Date.parse(a.expiresAt), operation.expires);
        oauthConsentNeed(Date.now() < expires && BigInt(Date.now()) * 1000000n >= issued - 1000000000n);
        await oauthConsentCookie(operation); operation.current();
        oauthConsentPending = {requestOriginal: reply.requestOriginal, request, options: {publicKey: {...key, timeout: 30000}},
          actor: operation.actor, expires, until: Math.min(operation.until, performance.now() + expires - Date.now()),
          provider: {id: provider.id, authorizationUrl: provider.authorizationUrl, redirectUri: provider.redirectUri}};
        oauthConsentSent = false;
        oauthConsentMessage('Prepared for ' + request.credentialName + ' via ' + provider.displayName + '. Before ' + new Date(expires).toISOString()
          + ', explicitly use a fresh passkey to open the provider once. No credential is active.');
      } catch (_) {
        oauthConsentPending = null; if (oauthConsentSent) oauthConsentBlocked = true;
        oauthConsentMessage('Consent preparation failed, expired or changed. Nothing is automatically restarted; no raw response or ciphertext is displayed.', true);
      } finally { operation?.close(); }
    }
    async function oauthConsentStart() {
      let operation = null, held = null, assertion = null, original = null;
      try {
        held = oauthConsentPending; oauthConsentNeed(oauthConsentLegacySelected() && held !== null); operation = oauthConsentBegin();
        const current = () => { operation.current(); oauthConsentNeed(held === oauthConsentPending && held.actor === operation.actor
          && Date.now() < held.expires && performance.now() < held.until); };
        await oauthConsentCookie(operation); current(); oauthConsentNeed(window.PublicKeyCredential && navigator.credentials);
        const key = held.options.publicKey;
        const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions({publicKey:
          {...key, allowCredentials: key.allowCredentials.map(item => ({...item}))}})});
        current(); oauthConsentNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
          && credential.rawId.byteLength <= 3072 && credential.id === key.allowCredentials[0].id && bytesToB64(credential.rawId) === credential.id);
        assertion = credentialToJson(credential); workloadIssuanceAssertionOriginal(assertion, held.options);
        const mfa = JSON.stringify({oauthExchangeProfile: oauthConsentSchema, assertion});
        oauthConsentNeed(new TextEncoder().encode(mfa).byteLength <= 16 * 1024);
        await oauthConsentCookie(operation); current();
        original = '{"apiVersion":' + JSON.stringify(oauthConsentSchema) + ',"request":' + held.requestOriginal + ',"mfa":' + mfa + '}';
        const reply = await oauthConsentRequest('/api/oauth/start', original, { ...operation, current }, () => { oauthConsentSent = true; });
        current(); const v = reply.value, r = held.request;
        oauthConsentNeed(reply.status === 200 && oauthConsentClosed(v, ['provider', 'authorizationUrl', 'state', 'expiresAtEpoch', 'redirectUri', 'scopes'])
          && v.provider === held.provider.id && v.redirectUri === held.provider.redirectUri
          && typeof v.state === 'string' && /^[0-9a-f]{32}_[A-Za-z0-9_-]{43}$/.test(v.state)
          && v.state.slice(0, 32) === r.exchangeId.replaceAll('-', '')
          && await workloadIssuanceHash(new TextEncoder().encode(v.state)) === r.stateSha256
          && oauthConsentInteger(v.expiresAtEpoch) === oauthConsentInteger(r.contactExpiresAtEpochNs) / 1000000000n
          && oauthConsentSame(v.scopes, r.scopes) && oauthConsentText(v.authorizationUrl, 16384));
        const url = new URL(v.authorizationUrl), expected = new URL(held.provider.authorizationUrl);
        const query = url.searchParams;
        oauthConsentNeed(url.protocol === 'https:' && !url.username && !url.password && !url.hash
          && url.origin === expected.origin && url.pathname === expected.pathname
          && [...query.keys()].length === new Set(query.keys()).size && query.get('state') === v.state
          && query.get('redirect_uri') === v.redirectUri && query.get('response_type') === 'code'
          && query.get('scope') === r.scopes.join(' ') && oauthConsentText(query.get('client_id'), 4096)
          && query.get('code_challenge_method') === 'S256' && /^[A-Za-z0-9_-]{43}$/.test(query.get('code_challenge') || ''));
        await oauthConsentCookie(operation); current();
        oauthConsentPending = null; oauthConsentBlocked = true;
        oauthConsentMessage('Definite prepare received. Leaving for the exact provider consent URL; no activation is claimed.');
        window.location.assign(url.href);
      } catch (_) {
        oauthConsentPending = null; if (oauthConsentSent) oauthConsentBlocked = true;
        oauthConsentMessage(oauthConsentSent ? 'Start was sent but completion or context is unknown. No retry or navigation is allowed.'
          : 'Passkey or current context did not complete. Prepared consent discarded; no start POST was sent.', true);
      } finally { assertion = original = held = null; operation?.close(); }
    }
    function initOAuthConsent() {
      $('oauth-consent-start').addEventListener('click', oauthConsentStart);
      $('oauth-consent-discard').addEventListener('click', () => { oauthConsentInvalidate('Prepared consent discarded explicitly.'); renderOAuthConsent(); });
      $('oauth-consent-show-auth').addEventListener('click', () => { $('admin-token').hidden = false; $('admin-token').focus(); });
      $('oauth-form').addEventListener('input', () => { oauthConsentInvalidate('Consent form changed.'); renderOAuthConsent(); });
      $('oauth-form').addEventListener('change', () => { oauthConsentInvalidate('Consent selection changed.'); renderOAuthConsent(); });
      $('admin-token').addEventListener('input', () => { oauthConsentInvalidate('Entered credentials changed.'); renderOAuthConsent(); });
      const timer = setInterval(renderOAuthConsent, 500);
      window.addEventListener('pagehide', () => { clearInterval(timer); oauthConsentInvalidate('Page left; no consent continuation retained.'); });
      renderOAuthConsent();
    }
"""

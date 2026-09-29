"""Explicit encrypted-native consent navigation, without parent private inputs."""


def provider_status_with_custody():
    from serverware.oauth import provider_status
    from serverware import oauth_application_owner
    from serverware import oauth_reconnect_owner
    result = provider_status()
    for provider in result:
        if oauth_reconnect_owner.selected() and oauth_application_owner.measured_selected(provider["id"]):
            provider["consentProfile"] = "serverware.oauthReconnectApprovalOptions/v1"
        elif oauth_application_owner.setup_selected(provider["id"]):
            provider["consentProfile"] = "serverware.nativeOAuthSetupConsentOptions/v1"
        elif oauth_application_owner.measured_selected(provider["id"]):
            provider["consentProfile"] = "serverware.nativeOAuthConsentOptions/v1"
    return result


MEASURED_OAUTH_CONSENT_HTML = r"""
          <div id="native-oauth-controls" hidden>
            <p class="hint">Confidential consent uses the explicitly provisioned native HTTPS origin. A cold-selected Setup profile binds a controlled draft session; the unbound profile cannot adopt it. Reconnect remains separate.</p>
            <button id="native-oauth-review" type="button" disabled>Review returned native preparation</button>
            <button id="native-oauth-authorize" type="button" disabled>Fresh passkey + authorize once</button>
            <button id="native-oauth-discard" type="button" class="secondary">Discard native preparation</button>
            <p id="native-oauth-status" class="hint" role="status" aria-live="polite">No native preparation selected.</p>
          </div>
"""

MEASURED_OAUTH_CONSENT_SCRIPT = r"""
    const nativeOAuthSchema = 'serverware.nativeOAuthConsentOptions/v1';
    const nativeOAuthSetupSchema = 'serverware.nativeOAuthSetupConsentOptions/v1';
    let nativeOAuthReturned = null, nativeOAuthPrepared = null, nativeOAuthBlocked = false, nativeOAuthBusy = false;
    const nativeOAuthProvider = () => (state.oauthProviders || []).find(p => p.id === $('oauth-provider').value);
    const nativeOAuthSetupSelected = () => nativeOAuthProvider()?.consentProfile === nativeOAuthSetupSchema;
    const nativeOAuthSelected = () => [nativeOAuthSchema, nativeOAuthSetupSchema].includes(nativeOAuthProvider()?.consentProfile);
    function nativeOAuthContract() {
      oauthConsentNeed(nativeOAuthSelected());
      return nativeOAuthSetupSelected() ? {schema: nativeOAuthSetupSchema, prefix: '/api/setup/oauth/native',
        intent: 'serverware.nativeOAuthSetupIntentResponse/v1', draft: 'serverware.nativeOAuthSetupDraft/v1',
        action: 'credential.oauth.measured-setup-consent', statement: 'serverware.nativeOAuthSetupExchangeStatement/v1',
        prepare: 'oauth.measured-setup.prepare', response: 'serverware.nativeOAuthSetupExchangeResponse/v1'} :
        {schema: nativeOAuthSchema, prefix: '/api/oauth/native', intent: 'serverware.nativeOAuthIntentResponse/v1',
        draft: 'serverware.nativeOAuthDraft/v1', action: 'credential.oauth.measured-consent',
        statement: 'serverware.nativeOAuthExchangeStatement/v1', prepare: 'oauth.measured-exchange.prepare',
        response: 'serverware.nativeOAuthExchangeResponse/v1'};
    }
    const nativeOAuthMessage = text => { $('native-oauth-status').textContent = text; };
    function nativeOAuthOrigin(raw) {
      const url = new URL(raw); oauthConsentNeed(url.protocol === 'https:' && !url.username && !url.password
        && !url.port && url.pathname === '/' && !url.search && !url.hash && url.origin === raw && raw !== location.origin);
      return url.origin;
    }
    function nativeOAuthEncode(raw) {
      const bytes = new TextEncoder().encode(raw); oauthConsentNeed(bytes.length <= 1024 * 1024);
      let text = ''; for (let n = 0; n < bytes.length; n += 8192) text += String.fromCharCode(...bytes.subarray(n, n + 8192));
      return btoa(text).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    }
    function nativeOAuthDecode(raw) {
      oauthConsentNeed(typeof raw === 'string' && raw.length > 0 && raw.length <= 1024 * 1024 && /^[A-Za-z0-9_-]+$/.test(raw));
      const text = atob(raw.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - raw.length % 4) % 4));
      return new TextDecoder('utf-8', {fatal: true}).decode(Uint8Array.from(text, c => c.charCodeAt(0)));
    }
    async function nativeOAuthHash(value) {
      const raw = new TextEncoder().encode(oauthConsentCanonical(value));
      return 'sha256:' + Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', raw)), b => b.toString(16).padStart(2, '0')).join('');
    }
    function nativeOAuthDiscard(message) {
      nativeOAuthReturned = nativeOAuthPrepared = null;
      if (nativeOAuthBusy) nativeOAuthBlocked = true;
      nativeOAuthMessage(message); renderNativeOAuth();
    }
    function renderNativeOAuth() {
      if (!$('native-oauth-controls')) return;
      const selected = nativeOAuthSelected(); $('native-oauth-controls').hidden = !selected && nativeOAuthReturned === null;
      if (!selected) return;
      let allowed = false; try { oauthConsentActor(); allowed = true; } catch (_) {}
      $('oauth-consent-start').disabled = true;
      $('oauth-submit').textContent = 'Open confidential native preparation';
      $('oauth-submit').disabled = !allowed || nativeOAuthBusy || nativeOAuthBlocked || nativeOAuthReturned !== null || nativeOAuthPrepared !== null;
      $('native-oauth-review').disabled = !allowed || nativeOAuthBusy || nativeOAuthBlocked || nativeOAuthReturned === null || nativeOAuthPrepared !== null;
      $('native-oauth-authorize').disabled = !allowed || nativeOAuthBusy || nativeOAuthBlocked || nativeOAuthPrepared === null;
      if (nativeOAuthPrepared && (Date.now() >= nativeOAuthPrepared.expires
          || nativeOAuthPrepared.scope !== sessionActivationAuthScope() || nativeOAuthPrepared.form !== oauthConsentFormPin()))
        nativeOAuthDiscard('Preparation expired or operator context changed. Nothing is replayed.');
    }
    async function nativeOAuthRequest(path, body, operation, sent = null) {
      oauthConsentNeed(['/api/oauth/native/intent', '/api/oauth/native/options', '/api/oauth/native/consent',
        '/api/setup/oauth/native/intent', '/api/setup/oauth/native/options', '/api/setup/oauth/native/consent',
        '/api/setup/oauth/create/draft', '/api/setup/oauth/create/options', '/api/setup/oauth/create', '/api/setup/oauth/audit-settle'].includes(path));
      const csrfReply = await oauthConsentRequest('/api/csrf', null, operation), csrf = csrfReply.value;
      oauthConsentNeed(csrfReply.status === 200 && oauthConsentClosed(csrf, ['ok', 'token', 'cookie', 'header'])
        && csrf.ok === true && csrf.cookie === 'serverware_csrf' && csrf.header === 'X-Serverware-CSRF-Token'
        && oauthConsentText(csrf.token, 1024));
      operation.current(); const original = oauthConsentCanonical(body);
      oauthConsentNeed(new TextEncoder().encode(original).length <= 3 * 1024 * 1024);
      if (sent) sent();
      const response = await fetch(path, {method: 'POST', credentials: 'same-origin', mode: 'same-origin', redirect: 'error',
        cache: 'no-store', signal: operation.signal, headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: original});
      operation.current(); oauthConsentNeed(response.status === 200 && response.body
        && /^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || ''));
      const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', {fatal: true});
      let raw = '', length = 0, done = false;
      try { for (;;) { operation.current(); const item = await reader.read(); operation.current();
        if (item.done) {done = true; break;} length += item.value.length; oauthConsentNeed(length <= 8 * 1024 * 1024);
        raw += decoder.decode(item.value, {stream: true}); }
        raw += decoder.decode(); return oauthConsentParse(raw, 8 * 1024 * 1024).value;
      } finally {if (!done) {try {await reader.cancel();} catch (_) {}} reader.releaseLock(); raw = '';}
    }
    async function nativeOAuthBegin() {
      let operation = null;
      try {
        oauthConsentNeed(nativeOAuthSelected() && !nativeOAuthBusy && !nativeOAuthBlocked && nativeOAuthReturned === null);
        operation = oauthConsentBegin(); nativeOAuthBusy = true; await oauthConsentCookie(operation);
        const metadata = oauthConsentParse($('oauth-metadata').value || '{}').value;
        oauthConsentNeed(metadata && typeof metadata === 'object' && !Array.isArray(metadata)
          && !Object.hasOwn(metadata, 'oauth_application_owner'));
        const body = {provider: nativeOAuthProvider().id, credentialName: $('oauth-credential-name').value || null,
          scopes: parseOAuthScopes($('oauth-scopes').value), metadata};
        const contract = nativeOAuthContract();
        if (nativeOAuthSetupSelected()) {
          oauthConsentNeed(state.oauthSetupSessionId && state.setupSession?.id === state.oauthSetupSessionId
            && state.setupSession.phase === 'created' && state.setupSession.revision === 0);
          body.sessionId = state.setupSession.id; body.revision = 0;
        }
        const value = await nativeOAuthRequest(contract.prefix + '/intent', body, operation);
        oauthConsentNeed(oauthConsentClosed(value, ['apiVersion', 'callbackOrigin', 'portalOrigin', 'intent'])
          && value.apiVersion === contract.intent && value.portalOrigin === location.origin
          && value.intent?.providerId === body.provider && value.intent?.requesterId === operation.actor);
        const origin = nativeOAuthOrigin(value.callbackOrigin), provider = nativeOAuthProvider();
        oauthConsentNeed(provider.redirectUri === origin + '/oauth/callback/' + provider.id);
        await oauthConsentCookie(operation); operation.current(); saveOAuthDraft(); nativeOAuthBlocked = true;
        location.assign(origin + '/oauth/begin#original=' + nativeOAuthEncode(oauthConsentCanonical(value.intent)));
      } catch (_) {nativeOAuthMessage('Native preparation did not complete. No provider request or automatic fallback was made.');}
      finally {nativeOAuthBusy = false; operation?.close(); renderNativeOAuth();}
    }
    async function nativeOAuthReview() {
      let operation = null;
      try {
        oauthConsentNeed(nativeOAuthSelected() && nativeOAuthReturned !== null && !nativeOAuthBusy && !nativeOAuthBlocked);
        operation = oauthConsentBegin(); nativeOAuthBusy = true; await oauthConsentCookie(operation);
        const returned = nativeOAuthReturned, args = returned.arguments, request = args?.request, provider = nativeOAuthProvider(), contract = nativeOAuthContract();
        oauthConsentNeed(oauthConsentClosed(returned, ['apiVersion', 'arguments', 'callbackOrigin', 'portalOrigin'])
          && returned.apiVersion === contract.draft && returned.portalOrigin === location.origin
          && nativeOAuthOrigin(returned.callbackOrigin) + '/oauth/callback/' + provider.id === provider.redirectUri
          && oauthConsentClosed(args, ['action', 'resource_id', 'payload_digest', 'actor_id', 'request', 'approval_id', 'credential_policy',
            'enrollment_original', 'control_plane_configuration_digest', 'assignment_original', 'native_evidence'])
          && args.action === contract.action && args.actor_id === operation.actor && args.approval_id === null
          && args.assignment_original === null && request?.exchangeId === args.resource_id && request.providerId === provider.id
          && request.redirectUri === provider.redirectUri && request.portalOrigin === location.origin && request.callbackOrigin === returned.callbackOrigin
          && oauthConsentText(request.credentialName, 256) && Array.isArray(request.scopes) && request.scopes.every(v => oauthConsentText(v, 1024)));
        const name = $('oauth-credential-name').value.trim();
        oauthConsentNeed(!name || request.credentialName === name);
        const scopes = parseOAuthScopes($('oauth-scopes').value);
        oauthConsentNeed(JSON.stringify(request.scopes) === JSON.stringify([...(scopes.length ? scopes : provider.defaultScopes)].sort()));
        const metadata = oauthConsentParse($('oauth-metadata').value || '{}').value;
        oauthConsentNeed(request.metadata && Object.keys(request.metadata).length === Object.keys(metadata).length + 1
          && Object.hasOwn(request.metadata, 'oauth_application_owner') && Object.keys(metadata).every(k => oauthConsentSame(metadata[k], request.metadata[k])));
        oauthConsentNeed(args.payload_digest === await nativeOAuthHash(request)); operation.current();
        const statement = args.native_evidence?.statement;
        oauthConsentNeed(statement?.apiVersion === contract.statement && statement.phase === 'draft'
          && statement.exchangeId === args.resource_id && statement.providerId === provider.id && statement.callbackOrigin === returned.callbackOrigin);
        if (nativeOAuthSetupSelected()) {
          nativeSetupBinding(request.setupBinding);
          oauthConsentNeed(request.setupBinding.sessionId === state.oauthSetupSessionId && request.setupBinding.ownerId === operation.actor
            && oauthConsentInteger(request.setupBinding.revision) === 0n
            && statement.setupBindingSha256 === await nativeOAuthHash(request.setupBinding));
        } else oauthConsentNeed(!Object.hasOwn(request, 'setupBinding'));
        const end = oauthConsentInteger(statement.expiresAtEpochNs), start = oauthConsentInteger(statement.issuedAtEpochNs);
        oauthConsentNeed(end > start && end - start <= 30000000000n && BigInt(Date.now()) * 1000000n < end);
        const options = await nativeOAuthRequest(contract.prefix + '/options', {apiVersion: contract.schema, arguments: args}, operation);
        const key = options.publicKey, binding = options.serverware;
        oauthConsentNeed(oauthConsentClosed(options, ['publicKey', 'serverware'])
          && oauthConsentClosed(binding, ['schema', 'operation', 'operationId', 'challengeId', 'credentialRecordId', 'payloadDigest', 'expiresAt'])
          && binding.schema === contract.schema && binding.operation === contract.prepare
          && binding.payloadDigest === args.payload_digest && oauthConsentDigest(binding.operationId)
          && oauthConsentText(binding.challengeId, 256) && oauthConsentText(binding.credentialRecordId, 256)
          && oauthConsentClosed(key, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          && key.rpId === location.hostname && key.userVerification === 'required' && oauthConsentInteger(key.timeout) === 30000n
          && Array.isArray(key.allowCredentials) && key.allowCredentials.length === 1
          && oauthConsentClosed(key.allowCredentials[0], ['type', 'id']) && key.allowCredentials[0].type === 'public-key');
        const expires = Math.min(Number(end / 1000000n), Date.parse(binding.expiresAt)); oauthConsentNeed(Number.isFinite(expires) && Date.now() < expires);
        operation.current(); nativeOAuthPrepared = {args, contract, callbackOrigin: returned.callbackOrigin, options: {publicKey: {...key, timeout: 30000}},
          expires, scope: sessionActivationAuthScope(), form: oauthConsentFormPin(), actor: operation.actor};
        nativeOAuthMessage('Review: ' + request.credentialName + ' via ' + provider.displayName + '; scopes: ' + request.scopes.join(', ')
          + '. Fresh passkey approval is still required before the native origin may open provider consent.');
      } catch (_) {nativeOAuthPrepared = null; nativeOAuthMessage('Returned preparation failed, expired or changed. No consent effect was submitted.');}
      finally {nativeOAuthBusy = false; operation?.close(); renderNativeOAuth();}
    }
    async function nativeOAuthAuthorize() {
      let operation = null, assertion = null;
      try {
        const held = nativeOAuthPrepared; oauthConsentNeed(held && !nativeOAuthBusy && !nativeOAuthBlocked);
        operation = oauthConsentBegin(); nativeOAuthBusy = true;
        const current = () => {operation.current(); oauthConsentNeed(held === nativeOAuthPrepared && Date.now() < held.expires
          && held.scope === sessionActivationAuthScope() && held.form === oauthConsentFormPin() && held.actor === operation.actor);};
        await oauthConsentCookie(operation); current();
        const key = held.options.publicKey;
        const credential = await navigator.credentials.get({signal: operation.signal, publicKey: prepareRequestOptions({publicKey:
          {...key, allowCredentials: key.allowCredentials.map(item => ({...item}))}})});
        current(); oauthConsentNeed(credential?.type === 'public-key' && credential.rawId instanceof ArrayBuffer
          && credential.rawId.byteLength <= 3072 && credential.id === key.allowCredentials[0].id && bytesToB64(credential.rawId) === credential.id);
        assertion = credentialToJson(credential); workloadIssuanceAssertionOriginal(assertion, held.options);
        const mfa = {nativeOAuthConsentProfile: held.contract.schema, assertion};
        oauthConsentNeed(new TextEncoder().encode(oauthConsentCanonical(mfa)).length <= 16384);
        await oauthConsentCookie(operation); current();
        const reply = await nativeOAuthRequest(held.contract.prefix + '/consent', {apiVersion: held.contract.schema, arguments: held.args, mfa},
          {...operation, current}, () => {nativeOAuthBlocked = true;});
        current(); oauthConsentNeed(oauthConsentClosed(reply, ['apiVersion', 'requestOriginal', 'responseOriginal'])
          && reply.apiVersion === held.contract.response
          && /^[A-Za-z0-9_-]+$/.test(reply.requestOriginal) && /^[A-Za-z0-9_-]+$/.test(reply.responseOriginal));
        const original = oauthConsentCanonical({exchangeId: held.args.resource_id,
          originals: {requestOriginal: reply.requestOriginal, responseOriginal: reply.responseOriginal}});
        oauthConsentNeed(new TextEncoder().encode(original).length <= 768 * 1024);
        nativeOAuthPrepared = nativeOAuthReturned = null;
        location.assign(held.callbackOrigin + '/oauth/authorize#original=' + nativeOAuthEncode(original));
      } catch (_) {nativeOAuthPrepared = null; nativeOAuthMessage(nativeOAuthBlocked
          ? 'Consent was sent or its outcome is uncertain. No retry or alternate callback is allowed.' : 'Passkey or original context did not complete.');}
      finally {assertion = null; nativeOAuthBusy = false; operation?.close(); renderNativeOAuth();}
    }
    function initNativeOAuth() {
      const returnedProfile = location.hash.startsWith('#nativeOAuthSetupDraft=')
        ? {fragment: '#nativeOAuthSetupDraft=', draft: 'serverware.nativeOAuthSetupDraft/v1'}
        : location.hash.startsWith('#nativeOAuthDraft=')
          ? {fragment: '#nativeOAuthDraft=', draft: 'serverware.nativeOAuthDraft/v1'} : null;
      if (returnedProfile !== null) {
        try {
          const original = nativeOAuthDecode(location.hash.slice(returnedProfile.fragment.length));
          const returned = oauthConsentParse(original).value;
          oauthConsentNeed(returned.apiVersion === returnedProfile.draft);
          // Storage is data only. Review additionally requires the actual
          // cold-selected provider contract; the fragment cannot select it.
          nativeOAuthReturned = returned;
        }
        catch (_) {nativeOAuthBlocked = true; nativeOAuthMessage('Native preparation is malformed; no fallback.');}
        history.replaceState(null, '', location.pathname + location.search);
      }
      $('native-oauth-review').addEventListener('click', nativeOAuthReview);
      $('native-oauth-authorize').addEventListener('click', nativeOAuthAuthorize);
      $('native-oauth-discard').addEventListener('click', () => nativeOAuthDiscard('Native preparation explicitly discarded.'));
      for (const name of ['input', 'change']) $('oauth-form').addEventListener(name, () => nativeOAuthDiscard('Form changed; native preparation discarded.'));
      $('admin-token').addEventListener('input', () => nativeOAuthDiscard('Operator credentials changed; native preparation discarded.'));
      const timer = setInterval(renderNativeOAuth, 500);
      window.addEventListener('pagehide', () => {clearInterval(timer); nativeOAuthReturned = nativeOAuthPrepared = null; nativeOAuthBlocked = true;});
      renderNativeOAuth();
    }
"""

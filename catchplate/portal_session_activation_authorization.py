"""Cookie-only, explicit portal authorization for fixed activation actions.

Browser bindings are cancellation/approval data, never server authority. Every
attempt obtains new genuine options and assertions; activation has two separate
ceremonies. No automatic dispatch, approval retry or credential persistence.
"""


SESSION_ACTIVATION_AUTHORIZATION_SCRIPT = r"""
    const sessionActivationAuthorizationRoutes = Object.freeze({
      activate: Object.freeze({post: '/api/auth/session/activation',
        options: '/api/auth/session/activation/permission/options',
        schema: 'catchplate.oidcSessionActivationPermissionOptions/v1'}),
      recover: Object.freeze({post: '/api/auth/session/activation/recovery',
        schema: 'catchplate.oidcSessionActivationRecoveryOptions/v1'}),
      'activation-complete': Object.freeze({post: '/api/auth/session/activation/completion/recovery',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryOptions/v1', profile: 'activation'}),
      'consume-complete': Object.freeze({post: '/api/auth/session/activation/consume/completion/recovery',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryOptions/v1', profile: 'consume'}),
      consume: Object.freeze({post: '/api/auth/session/activation/completion/recovery/consume',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryConsumeOptions/v1',
        profile: 'activation', recoveryPurpose: 'consume'}),
      'release-proof': Object.freeze({post: '/api/auth/session/activation/consume/completion/recovery/release-proof',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryReleaseOptions/v1',
        profile: 'consume', recoveryPurpose: 'release-intent-proof'}),
      release: Object.freeze({post: '/api/auth/session/activation/consume/completion/recovery/release',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryDeliveryOptions/v1',
        profile: 'consume', recoveryPurpose: 'release'}),
      'retained-release': Object.freeze({post: '/api/auth/session/activation/consume/completion/recovery/retained-release',
        schema: 'catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryOptions/v1',
        profile: 'consume', recoveryPurpose: 'retained-release'})
    });
    const sessionActivationAuthorizationBindings = new WeakSet();
    const sessionActivationApprovalContinuations = new WeakMap();
    const sessionActivationPlanningOptionsPath = '/api/auth/session/webauthn/options';

    function sessionActivationClosed(value, fields) {
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length
        && fields.every((field) => Object.prototype.hasOwnProperty.call(value, field));
    }

    function sessionActivationText(value, maximum) {
      return typeof value === 'string' && value.length > 0 && value.length <= maximum
        && /^[\x21-\x7e]+$/.test(value);
    }

    function sessionActivationLocalDigest(value) {
      return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
    }

    function sessionActivationAuthorizationRoute(action, selected) {
      const route = action && Object.prototype.hasOwnProperty.call(sessionActivationAuthorizationRoutes, action.id)
        ? sessionActivationAuthorizationRoutes[action.id] : null;
      if (!route || action.postPath !== route.post || action.optionsPath !== (route.options || route.post + '/options')
          || !sessionActivationClosed(selected, ['localDigest']) || !sessionActivationLocalDigest(selected.localDigest)) {
        throw new Error('A fixed session action and retained finalization locator are required.');
      }
      return route;
    }

    function sessionActivationAuthorizationScope() {
      const auth = state.authStatus;
      if (!auth || typeof auth.userId !== 'string' || !auth.userId
          || !['pending_webauthn', 'active'].includes(auth.sessionState)
          || !Array.isArray(auth.roles) || auth.roles.some((role) => typeof role !== 'string')) {
        throw new Error('Refresh the browser-cookie session before requesting authorization.');
      }
      // Entered operator bearer credentials are neither identity nor transport
      // authority for these routes. The server rechecks the actual cookie.
      return JSON.stringify([auth.userId, auth.authMethod, auth.sessionState,
        auth.authenticated === true, auth.webauthnRequired === true, auth.roles]);
    }

    function sessionActivationRequireCurrent(stillCurrent) {
      if (typeof stillCurrent !== 'function' || stillCurrent() !== true) {
        throw new Error('The selected target or browser authentication changed; no continuation is allowed.');
      }
    }

    async function sessionActivationReadAuthorization(response, maximum, stillCurrent) {
      sessionActivationRequireCurrent(stillCurrent);
      if (!(response instanceof Response) || !response.body
          || !/^application\/json(?:\s*;|$)/i.test(response.headers.get('Content-Type') || '')) {
        throw new Error('The server did not return bounded JSON authorization options.');
      }
      const length = response.headers.get('Content-Length');
      if (length !== null && (!/^[0-9]+$/.test(length) || Number(length) > maximum)) {
        throw new Error('Authorization options exceed the response limit.');
      }
      const reader = response.body.getReader();
      const decoder = new TextDecoder('utf-8', {fatal: true});
      let text = '', size = 0, complete = false;
      try {
        for (;;) {
          sessionActivationRequireCurrent(stillCurrent);
          const item = await reader.read();
          sessionActivationRequireCurrent(stillCurrent);
          if (item.done) { complete = true; break; }
          size += item.value.byteLength;
          if (size > maximum) throw new Error('Authorization options exceed the response limit.');
          text += decoder.decode(item.value, {stream: true});
        }
        text += decoder.decode();
        sessionActivationRequireCurrent(stillCurrent);
        return JSON.parse(text);
      } finally {
        if (!complete) { try { await reader.cancel(); } catch (_) {} }
        reader.releaseLock();
      }
    }

    async function sessionActivationPost(path, body, stillCurrent) {
      const fixed = Object.values(sessionActivationAuthorizationRoutes).some((route) =>
        path === route.post || path === (route.options || route.post + '/options'))
        || path === sessionActivationPlanningOptionsPath;
      if (!fixed) throw new Error('The session action route is not source selected.');
      sessionActivationRequireCurrent(stillCurrent);
      let original = JSON.stringify(body);
      const maximum = path === '/api/auth/session/activation' ? 256 * 1024 : 64 * 1024;
      if (typeof original !== 'string' || new TextEncoder().encode(original).byteLength > maximum) {
        throw new Error('The session action request exceeds its byte limit.');
      }
      let token = null;
      try {
        // Do not call ensureCsrfToken/sessionApi/api: those can select the
        // entered operator bearer. Always obtain CSRF for the actual cookie.
        const csrfResponse = await fetch('/api/csrf', {method: 'GET', mode: 'same-origin',
          credentials: 'same-origin', cache: 'no-store', redirect: 'error'});
        const csrf = await sessionActivationReadAuthorization(csrfResponse, 4096, stillCurrent);
        if (!csrfResponse.ok || !sessionActivationClosed(csrf, ['ok', 'token', 'cookie', 'header'])
            || csrf.ok !== true || !sessionActivationText(csrf.token, 1024)
            || csrf.header !== 'X-Catchplate-CSRF-Token' || !sessionActivationText(csrf.cookie, 256)) {
          throw new Error('Browser-cookie CSRF admission failed; no action request was sent.');
        }
        token = csrf.token;
        sessionActivationRequireCurrent(stillCurrent);
        const response = await fetch(path, {method: 'POST', mode: 'same-origin',
          credentials: 'same-origin', cache: 'no-store', redirect: 'error',
          headers: {'Content-Type': 'application/json', 'X-Catchplate-CSRF-Token': token}, body: original});
        sessionActivationRequireCurrent(stillCurrent);
        // The caller consumes the one response. No status causes a resend.
        return response;
      } finally {
        original = ''; token = null; // Dropped references, not a guaranteed wipe.
      }
    }

    function sessionActivationCredentialId(value) {
      if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{1,4096}$/.test(value)
          || value.length % 4 === 1) throw new Error('The server target key is invalid.');
      const bytes = b64ToBytes(value);
      if (bytesToB64(bytes) !== value) throw new Error('The server target key is not canonical.');
      return value;
    }

    function sessionActivationPublicKey(value, soleTarget) {
      if (!sessionActivationClosed(value, ['challenge', 'rpId', 'allowCredentials', 'timeout', 'userVerification'])
          || !sessionActivationText(value.rpId, 253) || !Number.isSafeInteger(value.timeout)
          || value.timeout < 1 || value.timeout > 600000
          || !['required', 'preferred', 'discouraged'].includes(value.userVerification)
          || !Array.isArray(value.allowCredentials) || value.allowCredentials.length < 1
          || value.allowCredentials.length > 64 || (soleTarget && value.allowCredentials.length !== 1)) {
        throw new Error('The server did not return a bounded target-key ceremony.');
      }
      sessionActivationCredentialId(value.challenge);
      const ids = value.allowCredentials.map((item) => {
        if (!item || typeof item !== 'object' || Array.isArray(item) || item.type !== 'public-key'
            || Object.keys(item).some((key) => !['id', 'type', 'transports'].includes(key))
            || (item.transports !== undefined && (!Array.isArray(item.transports) || item.transports.length > 8
              || item.transports.some((transport) => !sessionActivationText(transport, 32))))) {
          throw new Error('The server target-key descriptor is invalid.');
        }
        return sessionActivationCredentialId(item.id);
      });
      if (new Set(ids).size !== ids.length) throw new Error('The server returned duplicate target keys.');
      return ids;
    }

    function sessionActivationSameBinding(left, right) {
      return sessionActivationAuthorizationBindings.has(left) && sessionActivationAuthorizationBindings.has(right)
        && JSON.stringify(left) === JSON.stringify(right);
    }

    function sessionActivationBinding(action, selected, options, authScope) {
      const route = sessionActivationAuthorizationRoute(action, selected);
      const fields = ['schema', 'purpose', 'localDigest', 'action', 'resourceId', 'payloadDigest',
        'publicKey', 'automaticRetryAllowed'];
      if (route.profile) fields.push('completionProfile');
      if (route.recoveryPurpose) fields.push('recoveryPurpose');
      const activation = action.id === 'activate';
      if (!sessionActivationClosed(options, fields) || options.schema !== route.schema
          || options.purpose !== (activation ? 'authorize-oidc-session-activation' : 'recover-oidc-session-activation')
          || options.localDigest !== selected.localDigest
          || options.action !== (activation ? 'webauthn.oidc-session.activation.authorize' : 'webauthn.oidc-session.activation.recover')
          || !sessionActivationText(options.resourceId, 1024) || !sessionActivationLocalDigest(options.payloadDigest)
          || options.automaticRetryAllowed !== false || options.completionProfile !== route.profile
          || options.recoveryPurpose !== route.recoveryPurpose) {
        throw new Error('Authorization options do not match the selected action and target.');
      }
      const [credentialId] = sessionActivationPublicKey(options.publicKey, true);
      const binding = Object.freeze({id: action.id, postPath: route.post,
        optionsPath: route.options || route.post + '/options', localDigest: selected.localDigest,
        schema: options.schema, purpose: options.purpose, action: options.action,
        resourceId: options.resourceId, payloadDigest: options.payloadDigest,
        completionProfile: route.profile || null, recoveryPurpose: route.recoveryPurpose || null,
        credentialId, rpId: options.publicKey.rpId, userVerification: options.publicKey.userVerification, authScope});
      sessionActivationAuthorizationBindings.add(binding);
      return binding;
    }

    async function sessionActivationAssertion(publicKey, credentialId, stillCurrent) {
      sessionActivationRequireCurrent(stillCurrent);
      if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('WebAuthn is unavailable in this browser.');
      const target = publicKey.allowCredentials.find((item) => item.id === credentialId);
      if (!target) throw new Error('The fresh ceremony does not authorize the held target key.');
      // Narrow the actual server list, never add a posted/entered key. Clone
      // before the existing decoder mutates challenge and credential IDs.
      const options = {publicKey: {...publicKey, allowCredentials: [{...target}]}};
      const credential = await navigator.credentials.get({publicKey: prepareRequestOptions(options)});
      sessionActivationRequireCurrent(stillCurrent);
      if (!credential || credential.type !== 'public-key' || !(credential.rawId instanceof ArrayBuffer)
          || credential.rawId.byteLength > 3072 || bytesToB64(credential.rawId) !== credentialId
          || credential.id !== credentialId || !credential.response) {
        throw new Error('The fresh assertion does not belong to the selected target key.');
      }
      let total = 0;
      for (const name of ['clientDataJSON', 'authenticatorData', 'signature', 'userHandle']) {
        const value = credential.response[name];
        if (value == null && name === 'userHandle') continue;
        if (!(value instanceof ArrayBuffer) || value.byteLength > 32 * 1024) {
          throw new Error('The authenticator response exceeds its source limit.');
        }
        total += value.byteLength;
      }
      if (total > 40 * 1024) throw new Error('The authenticator response exceeds its source limit.');
      const assertion = credentialToJson(credential);
      if (new TextEncoder().encode(JSON.stringify(assertion)).byteLength > 60 * 1024) {
        throw new Error('The fresh assertion exceeds its request limit.');
      }
      return assertion;
    }

    async function sessionActivationAuthorize(action, selected, stillCurrent, approvalId = null, previousBinding = null) {
      const route = sessionActivationAuthorizationRoute(action, selected);
      const authScope = sessionActivationAuthorizationScope();
      const current = () => stillCurrent() === true && authScope === sessionActivationAuthorizationScope();
      sessionActivationRequireCurrent(current);
      if ((approvalId === null) !== (previousBinding === null)
          || (approvalId !== null && (!sessionActivationText(approvalId, 4096)
            || !sessionActivationAuthorizationBindings.has(previousBinding)
            || sessionActivationApprovalContinuations.get(previousBinding) !== approvalId))) {
        throw new Error('Approval continuation requires the original in-page action binding.');
      }
      if (previousBinding !== null) sessionActivationApprovalContinuations.delete(previousBinding);
      const activation = action.id === 'activate';
      const carrier = activation
        ? {purpose: 'authorize-oidc-session-activation', localDigest: selected.localDigest}
        : {schema: 'catchplate.oidcSessionActivationRecoveryRequest/v1',
          purpose: 'recover-oidc-session-activation', localDigest: selected.localDigest};
      const response = await sessionActivationPost(action.optionsPath, carrier, current);
      const options = await sessionActivationReadAuthorization(response, 64 * 1024, current);
      if (!response.ok) throw new Error('Fresh authorization options were refused; no action was submitted.');
      const binding = sessionActivationBinding(action, selected, options, authScope);
      if (previousBinding !== null && !sessionActivationSameBinding(previousBinding, binding)) {
        throw new Error('The action, target, key or authentication changed; discard the prior approval.');
      }
      const assertion = await sessionActivationAssertion(options.publicKey, binding.credentialId, current);
      const mfa = approvalId === null ? {assertion} : {assertion, approvalId};
      let body;
      if (activation) {
        // This is a second genuine challenge and a second user ceremony, not
        // the permission assertion relabelled as planning evidence.
        const planningResponse = await sessionActivationPost(sessionActivationPlanningOptionsPath, {}, current);
        const planning = await sessionActivationReadAuthorization(planningResponse, 64 * 1024, current);
        if (!planningResponse.ok || !sessionActivationClosed(planning, ['publicKey', 'catchplate'])
            || !sessionActivationClosed(planning.catchplate, ['challenge_id', 'payload_digest'])
            || !sessionActivationText(planning.catchplate.challenge_id, 1024)
            || planning.catchplate.challenge_id === binding.resourceId
            || !sessionActivationLocalDigest(planning.catchplate.payload_digest)
            || planning.publicKey?.challenge === options.publicKey.challenge
            || planning.publicKey?.rpId !== binding.rpId) {
          throw new Error('The separate session-planning challenge is invalid; no activation was submitted.');
        }
        const targets = sessionActivationPublicKey(planning.publicKey, false);
        if (!targets.includes(binding.credentialId)) throw new Error('The planning challenge lacks the held target key.');
        const planningAssertion = await sessionActivationAssertion(planning.publicKey, binding.credentialId, current);
        body = {schema: 'catchplate.oidcSessionActivationHttpRequest/v1', purpose: 'dispatch-oidc-session-activation',
          localDigest: selected.localDigest, mfa,
          planning: {assertion: planningAssertion, challengeId: planning.catchplate.challenge_id}};
      } else {
        body = {...carrier, mfa};
      }
      sessionActivationRequireCurrent(current);
      // Only the UI's separate explicit action dispatch sends this carrier.
      return Object.freeze({body, binding});
    }

    function sessionActivationApproval(status, payload, action, selected, binding) {
      try {
        const route = sessionActivationAuthorizationRoute(action, selected);
        if (status !== 428 || !sessionActivationAuthorizationBindings.has(binding)
            || binding.id !== action.id || binding.postPath !== route.post
            || binding.localDigest !== selected.localDigest
            || binding.authScope !== sessionActivationAuthorizationScope()
            || !sessionActivationClosed(payload, ['detail'])) return null;
        const detail = payload.detail;
        if (!sessionActivationClosed(detail, ['schema', 'error', 'approvalId', 'action', 'resourceId',
              'payloadDigest', 'dispatchState', 'automaticRetryAllowed', 'freshAuthorizationRequired'])
            || detail.schema !== 'catchplate.oidcSessionActivationApprovalRequired/v1'
            || detail.error !== 'control_plane_approval_required' || !sessionActivationText(detail.approvalId, 4096)
            || detail.action !== binding.action || detail.resourceId !== binding.resourceId
            || detail.payloadDigest !== binding.payloadDigest || detail.dispatchState !== 'approval-required'
            || detail.automaticRetryAllowed !== false || detail.freshAuthorizationRequired !== true) return null;
        sessionActivationApprovalContinuations.set(binding, detail.approvalId);
        return detail.approvalId;
      } catch (_) { return null; }
    }
"""

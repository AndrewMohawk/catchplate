"""Embedded strict, bounded portal outcomes and read-only target confirmation."""

SESSION_ACTIVATION_CONFIRMATION_SCRIPT = r"""
    const sessionActivationOutcomeSpecs = Object.freeze({
      'activate': ['/api/auth/session/activation', null, null, null],
      'recover': ['/api/auth/session/activation/recovery', 'catchplate.oidcSessionActivationRecoveryResponse/v1', 'recover-oidc-session-activation', 'recovered'],
      'activation-complete': ['/api/auth/session/activation/completion/recovery', 'catchplate.oidcSessionActivationCompletionRecoveryResponse/v1', 'recover-oidc-session-activation-completion', 'completion-controls-reconciled'],
      'consume-complete': ['/api/auth/session/activation/consume/completion/recovery', 'catchplate.oidcSessionActivationCompletionRecoveryResponse/v1', 'recover-oidc-session-activation-completion', 'completion-controls-reconciled'],
      'consume': ['/api/auth/session/activation/completion/recovery/consume', 'catchplate.oidcSessionActivationCompletionRecoveryConsumeResponse/v1', 'consume', 'consume-completion-acknowledged'],
      'release-proof': ['/api/auth/session/activation/consume/completion/recovery/release-proof', 'catchplate.oidcSessionActivationCompletionRecoveryReleaseResponse/v1', 'release-intent-proof', 'release-intent-proof-retained'],
      'release': ['/api/auth/session/activation/consume/completion/recovery/release', 'catchplate.oidcSessionActivationCompletionRecoveryDeliveryResponse/v1', 'release', 'released'],
      'retained-release': ['/api/auth/session/activation/consume/completion/recovery/retained-release', 'catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryResponse/v1', 'retained-release', 'recovered']
    });

    function sessionActivationResult(kind, detail, canConfirm = false) {
      return Object.freeze({kind, detail, canConfirm});
    }
    function sessionActivationUnknown() {
      return sessionActivationResult('unknown', 'Outcome or current session is unknown. Do not retry the action automatically. An explicit read-only target check is available.', true);
    }
    function sessionActivationExact(value, fields) {
      return value !== null && typeof value === 'object' && !Array.isArray(value)
        && Object.keys(value).length === fields.length
        && fields.every(key => Object.prototype.hasOwnProperty.call(value, key));
    }
    function sessionActivationOutcomeSelection(action, selected) {
      const spec = action && Object.prototype.hasOwnProperty.call(sessionActivationOutcomeSpecs, action.id)
        ? sessionActivationOutcomeSpecs[action.id] : null;
      if (!spec || action.postPath !== spec[0] || !sessionActivationExact(selected, ['localDigest'])
          || typeof selected.localDigest !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(selected.localDigest)) {
        throw new Error('Invalid source-selected activation action');
      }
      return spec;
    }

    // Public replies contain only objects and scalar strings/booleans/null.
    // Reject duplicate keys instead of letting JSON.parse silently choose one.
    function sessionActivationReplyJSON(text) {
      let offset = 0, nodes = 0;
      const white = () => { while (/^[\x20\t\r\n]$/.test(text[offset] || 'x')) offset++; };
      function string() {
        const start = offset++;
        while (offset < text.length) {
          const point = text[offset++];
          if (point === '\\') { offset++; continue; }
          if (point === '"') return JSON.parse(text.slice(start, offset));
        }
        throw new Error('Truncated public response');
      }
      function value(depth) {
        white();
        if (++nodes > 64 || depth > 3) throw new Error('Public response structure exceeds its bound');
        if (text[offset] === '"') return string();
        for (const [literal, result] of [['true', true], ['false', false], ['null', null]]) {
          if (text.slice(offset, offset + literal.length) === literal) { offset += literal.length; return result; }
        }
        if (text[offset++] !== '{') throw new Error('Unexpected public response value');
        const result = {};
        white();
        if (text[offset] === '}') { offset++; return Object.freeze(result); }
        for (let count = 0; count < 16; count++) {
          white();
          if (text[offset] !== '"') throw new Error('Invalid public response key');
          const key = string();
          if (Object.prototype.hasOwnProperty.call(result, key)) throw new Error('Duplicate public response key');
          white();
          if (text[offset++] !== ':') throw new Error('Invalid public response separator');
          Object.defineProperty(result, key, {value: value(depth + 1), enumerable: true});
          white();
          const end = text[offset++];
          if (end === '}') return Object.freeze(result);
          if (end !== ',') throw new Error('Invalid public response object');
        }
        throw new Error('Too many public response fields');
      }
      const result = value(0);
      white();
      if (offset !== text.length) throw new Error('Trailing public response bytes');
      return result;
    }

    async function sessionActivationReadReply(response, path, stillCurrent) {
      if (!stillCurrent() || !(response instanceof Response) || response.redirected
          || response.url !== new URL(path, location.origin).href
          || response.headers.get('content-type') !== 'application/json' || !response.body) {
        throw new Error('Public response source differs');
      }
      const length = response.headers.get('content-length');
      if (length !== null && (!/^[0-9]{1,6}$/.test(length) || Number(length) > 32768)) {
        throw new Error('Public response exceeds its byte bound');
      }
      const reader = response.body.getReader(), chunks = [];
      let size = 0, complete = false;
      try {
        while (true) {
          if (!stillCurrent()) throw new Error('Selection changed');
          const part = await reader.read();
          if (!stillCurrent()) throw new Error('Selection changed');
          if (part.done) { complete = true; break; }
          if (!(part.value instanceof Uint8Array) || part.value.length > 32768 - size) {
            throw new Error('Public response exceeds its byte bound');
          }
          chunks.push(part.value); size += part.value.length;
        }
      } finally {
        if (!complete) { try { await reader.cancel(); } catch (_) {} }
        reader.releaseLock();
      }
      if (!stillCurrent() || size < 2 || (length !== null && Number(length) !== size)) {
        throw new Error('Public response is incomplete');
      }
      const bytes = new Uint8Array(size);
      let cursor = 0;
      for (const chunk of chunks) { bytes.set(chunk, cursor); cursor += chunk.length; }
      return sessionActivationReplyJSON(new TextDecoder('utf-8', {fatal: true}).decode(bytes));
    }

    function sessionActivationClassify(action, value, selected, status) {
      const spec = sessionActivationOutcomeSelection(action, selected);
      if (status !== 200) return sessionActivationUnknown();
      if (action.id === 'activate') {
        return sessionActivationExact(value, ['ok', 'authenticated']) && value.ok === true && value.authenticated === true
          ? sessionActivationResult('delivery-unconfirmed', 'The activation endpoint reported delivery. The browser cookie still needs an explicit exact-target current check.', true)
          : sessionActivationUnknown();
      }
      const historical = ['activation-complete', 'consume-complete', 'consume', 'release-proof'].includes(action.id);
      const fields = ['schema', 'purpose', 'status', 'sessionState', 'automaticRetryAllowed'];
      if (historical) fields.push('tokenReleased');
      if (['activation-complete', 'consume-complete', 'release-proof'].includes(action.id)) fields.push('localDigest');
      if (['activation-complete', 'consume-complete'].includes(action.id)) fields.push('completionProfile');
      if (!sessionActivationExact(value, fields) || value.schema !== spec[1] || value.purpose !== spec[2]
          || value.status !== spec[3] || value.automaticRetryAllowed !== false
          || value.sessionState !== (historical ? 'unknown' : 'active')
          || (historical && value.tokenReleased !== false)
          || ('localDigest' in value && value.localDigest !== selected.localDigest)
          || ('completionProfile' in value && value.completionProfile !== (action.id === 'activation-complete' ? 'activation' : 'consume'))) {
        return sessionActivationUnknown();
      }
      return historical
        ? sessionActivationResult('history', 'Historical completion or preparation was acknowledged. This did not release a token or cookie; current session state remains unknown.', true)
        : sessionActivationResult('delivery-unconfirmed', 'The delivery endpoint reported success. The browser cookie still needs an explicit exact-target current check.', true);
    }

    async function sessionActivationOutcome(action, response, selected, stillCurrent, binding = null) {
      try {
        const spec = sessionActivationOutcomeSelection(action, selected);
        const value = await sessionActivationReadReply(response, spec[0], stillCurrent);
        if (!stillCurrent()) return sessionActivationUnknown();
        if (response.status === 428) {
          const approvalId = sessionActivationApproval(428, value, action, selected, binding);
          if (typeof approvalId === 'string') return Object.freeze({kind: 'approval-required',
            detail: 'Fresh approval is required; no automatic continuation.', canConfirm: false, approvalId});
        }
        return sessionActivationClassify(action, value, selected, response.status);
      } catch (_) { return sessionActivationUnknown(); }
    }

    async function sessionActivationConfirm(action, selected, stillCurrent) {
      try {
        sessionActivationOutcomeSelection(action, selected);
        if (!stillCurrent()) return sessionActivationUnknown();
        const path = '/api/auth/session/activation/confirmation';
        // Never use entered admin/bearer headers or a generic API wrapper.
        const csrfResponse = await fetch('/api/csrf', {method: 'GET', mode: 'same-origin',
          credentials: 'same-origin', cache: 'no-store', redirect: 'error'});
        const csrf = await sessionActivationReadReply(csrfResponse, '/api/csrf', stillCurrent);
        if (!stillCurrent() || csrfResponse.status !== 200
            || !sessionActivationExact(csrf, ['ok', 'token', 'cookie', 'header']) || csrf.ok !== true
            || typeof csrf.token !== 'string' || !csrf.token || csrf.token.length > 1024
            || csrf.cookie !== 'catchplate_csrf' || csrf.header !== 'X-Catchplate-CSRF-Token') {
          return sessionActivationUnknown();
        }
        const response = await fetch(path, {method: 'POST', credentials: 'same-origin', cache: 'no-store',
          redirect: 'error', headers: {'Content-Type': 'application/json', 'X-Catchplate-CSRF-Token': csrf.token},
          body: JSON.stringify({schema: 'catchplate.oidcSessionActivationConfirmationRequest/v1',
            purpose: 'confirm-current-oidc-session', localDigest: selected.localDigest})});
        const value = await sessionActivationReadReply(response, path, stillCurrent);
        if (!stillCurrent() || response.status !== 200 || !sessionActivationExact(value,
            ['schema', 'purpose', 'localDigest', 'status', 'sessionState', 'automaticRetryAllowed'])
            || value.schema !== 'catchplate.oidcSessionActivationConfirmationResponse/v1'
            || value.purpose !== 'confirm-current-oidc-session' || value.localDigest !== selected.localDigest
            || value.status !== 'current-target-active' || value.sessionState !== 'active'
            || value.automaticRetryAllowed !== false) return sessionActivationUnknown();
        return sessionActivationResult('current-target-active',
          'The current browser cookie was observed active for this exact retained user, session and credential. This is a read-only observation, not permission or proof that the preceding action delivered it.');
      } catch (_) { return sessionActivationUnknown(); }
    }
"""

"""Pending-cookie first-key capture, stopping at genuine retained preparation.

All three stages require separate clicks. Browser state is not authorization;
the unchanged server owns session, bootstrap, attestation and custody admission.
No legacy verification, automatic execution, stored secrets or retry is added.
"""


REGISTRATION_CAPTURE_HTML = r"""
      <section id="registration-capture-workspace" aria-labelledby="registration-capture-heading">
        <h2 id="registration-capture-heading" tabindex="-1">First hardware key for this pending OIDC session</h2>
        <p>Protected mode is a configuration selection, not readiness. Use this only for a subject with no credential history. Each step is separate; the server checks the actual pending cookie and original ceremony. Existing or revoked keys require their separate workflow.</p>
        <div class="toolbar">
          <button id="registration-capture-options" type="button">1. Request first-key options</button>
          <button id="registration-capture-hardware" type="button" disabled>2. Capture new hardware key</button>
          <button id="registration-capture-prepare" type="button" disabled>3. Authorize retained grant preparation</button>
          <button id="registration-capture-discard" class="secondary" type="button">Discard local capture</button>
        </div>
        <p id="registration-capture-status" role="status" aria-live="polite">No first-key request sent. A pending cookie, fresh bootstrap authorization and configured protected services are required.</p>
        <p class="hint">Options and hardware output stay only in this page's memory. Bootstrap credentials are masked and discarded after each purpose. Discarding or changing authentication cannot undo a sent request or permit its retry. A failed/lost response is uncertain; inspect retained state. A successful preparation fills only the evidence-grant local ID below, not proof of completed registration or session activation.</p>
        <a href="#registration-handoff-workspace">Separate retained registration actions</a>
      </section>
"""


REGISTRATION_CAPTURE_SCRIPT = r"""
    let registrationCapture = null;
    let registrationCaptureEpoch = 0;
    let registrationCaptureBusy = false;
    let registrationCaptureOptionsAttempted = false;
    const registrationCapturePurpose = 'authorize-registration-evidence-execution';

    function registrationCaptureEligible() {
      return !oidcSessionStatusUnknown && state.authStatus?.sessionActivationMode === 'protected'
        && state.authStatus?.sessionState === 'pending_webauthn'
        && state.authStatus?.webauthnRequired === true && state.authStatus?.authenticated === false;
    }

    function registrationCaptureMessage(message) {
      $('registration-capture-status').textContent = message;
    }

    function registrationCaptureInvalidate(message) {
      registrationCaptureEpoch += 1;
      const owner = registrationCapture;
      registrationCapture = null;
      if (owner) {
        owner.controller.abort();
        clearTimeout(owner.timer);
        owner.options = owner.attestation = null;
      }
      // Never unlock sent requests or another workflow's retained locators.
      if ($('registration-capture-status')) registrationCaptureMessage(message
        + ' Local capture discarded; sent outcomes remain unknown and attempts stay locked.');
    }

    function renderRegistrationCapture() {
      if (!$('registration-capture-workspace')) return;
      if (registrationCapture && (!registrationCaptureEligible()
          || registrationCapture.scope !== sessionActivationAuthScope()
          || registrationCapture.activationEpoch !== sessionActivationEpoch
          || registrationCapture.handoffEpoch !== registrationHandoffEpoch)) {
        registrationCaptureInvalidate('Authentication or another protected action changed.');
      }
      const blocked = !registrationCaptureEligible() || registrationCaptureBusy
        || oidcSessionActivationBusy || sessionActivationBusy || registrationHandoffBusy;
      $('operator-session-enroll').hidden = !registrationCaptureEligible();
      $('operator-session-enroll').disabled = blocked;
      $('registration-capture-options').disabled = blocked || registrationCaptureOptionsAttempted;
      $('registration-capture-hardware').disabled = blocked || registrationCapture?.phase !== 'options-held';
      $('registration-capture-prepare').disabled = blocked || registrationCapture?.phase !== 'captured';
    }

    function openProtectedRegistrationCapture() {
      renderRegistrationCapture();
      $('registration-capture-workspace').scrollIntoView({block: 'start', behavior: 'auto'});
      $('registration-capture-heading').focus();
      return {uiHandled: true}; // Navigation only, no request or hardware prompt.
    }

    function registrationCaptureOwner() {
      const owner = {epoch: registrationCaptureEpoch, scope: sessionActivationAuthScope(),
        activationEpoch: sessionActivationEpoch, handoffEpoch: registrationHandoffEpoch,
        controller: new AbortController(), options: null, attestation: null, phase: 'new',
        label: 'YubiKey', deadline: null,
        check() {
          if (registrationCapture !== owner || owner.epoch !== registrationCaptureEpoch
              || owner.controller.signal.aborted || !registrationCaptureEligible()
              || owner.scope !== sessionActivationAuthScope() || owner.activationEpoch !== sessionActivationEpoch
              || owner.handoffEpoch !== registrationHandoffEpoch || registrationHandoffBusy
              || sessionActivationBusy || (owner.deadline !== null && performance.now() >= owner.deadline)) {
            throw new Error('First-key context changed or expired. No stale capture or response will be used.');
          }
        }};
      return owner;
    }

    async function registrationCapturePost(owner, phase, body) {
      const path = phase === 'options' ? '/api/auth/session/webauthn/register/options'
        : phase === 'prepare' ? '/api/auth/session/webauthn/register/prepare-execution' : null;
      if (!path) throw new Error('Unknown first-key purpose');
      let options = null;
      try {
        owner.check();
        // Cookie-only CSRF even if the unrelated operator-token field is set.
        const csrfResponse = await fetch('/api/csrf', {credentials: 'same-origin', cache: 'no-store', signal: owner.controller.signal});
        owner.check();
        const csrf = await csrfResponse.json();
        owner.check();
        if (!csrfResponse.ok || typeof csrf?.token !== 'string' || !csrf.token || csrf.token.length > 1024) {
          throw new Error('Pending-cookie CSRF admission failed; no action sent.');
        }
        options = {method: 'POST', credentials: 'same-origin', cache: 'no-store', signal: owner.controller.signal,
          headers: {'Content-Type': 'application/json', 'X-Serverware-CSRF-Token': csrf.token}, body: JSON.stringify(body)};
        if (new TextEncoder().encode(options.body).length > 512 * 1024) throw new Error('First-key request exceeds its source bound.');
        owner.check();
        if (phase === 'options') {
          if (registrationCaptureOptionsAttempted) throw new Error('First-key options were already attempted.');
          registrationCaptureOptionsAttempted = true;
          owner.started = performance.now();
        }
        // Consume before dispatch, including an uncertain fetch/send failure.
        owner.phase = phase + '-attempted';
        const response = await fetch(path, options);
        owner.check();
        const value = await response.json();
        owner.check();
        if (!response.ok || response.status !== (phase === 'prepare' ? 202 : 200)) {
          throw new Error('First-key request refused or uncertain. No automatic retry; inspect retained state.');
        }
        return value;
      } finally {
        if (options) { options.body = ''; options.headers = {}; }
      }
    }

    async function registrationCaptureAction(kind) {
      if (registrationCaptureBusy || oidcSessionActivationBusy || sessionActivationBusy || registrationHandoffBusy) return {uiHandled: true};
      let owner = registrationCapture, body = null, bootstrap = null;
      try {
        if (!registrationCaptureEligible()) throw new Error('A confirmed protected pending cookie is required. No legacy fallback.');
        if (kind === 'options') {
          if (registrationCaptureOptionsAttempted || owner) throw new Error('This page already holds or attempted first-key options.');
          owner = registrationCaptureOwner();
          registrationCapture = owner;
        } else if (!owner || (kind === 'hardware' ? owner.phase !== 'options-held'
            : kind !== 'prepare' || owner.phase !== 'captured')) throw new Error('The preceding first-key stage is missing or already attempted.');
        owner.check();
        registrationCaptureBusy = oidcSessionActivationBusy = true;
        renderAuthStatus();
        owner.check();
        if (kind === 'hardware') {
          if (!window.PublicKeyCredential || !navigator.credentials) throw new Error('WebAuthn is unavailable.');
          owner.phase = 'hardware-attempted';
          const options = owner.options;
          owner.options = null;
          const credential = await navigator.credentials.create({publicKey: prepareCreationOptions(options), signal: owner.controller.signal});
          owner.check();
          owner.attestation = credentialToJson(credential);
          if (new TextEncoder().encode(JSON.stringify(owner.attestation)).length > 511 * 1024) {
            throw new Error('Hardware output exceeds its source request bound.');
          }
          owner.phase = 'captured';
          registrationCaptureMessage('Hardware output captured only in memory. Next, explicitly authorize grant preparation; nothing has executed or activated.');
        } else {
          if ($('webauthn-bootstrap-dialog').open) throw new Error('Finish the open bootstrap prompt first.');
          bootstrap = await requestWebAuthnBootstrapToken(owner.controller.signal);
          owner.check();
          if (typeof bootstrap !== 'string' || !bootstrap || bootstrap.length > 1024) throw new Error('Bootstrap authorization cancelled or invalid.');
          body = {label: owner.label, bootstrapToken: bootstrap};
          if (kind === 'prepare') Object.assign(body, {purpose: registrationCapturePurpose, response: owner.attestation});
          const value = await registrationCapturePost(owner, kind, body);
          owner.check();
          if (kind === 'options') {
            if (!value?.publicKey || typeof value.publicKey.challenge !== 'string' || !value.publicKey.challenge
                || typeof value.publicKey.user?.id !== 'string' || !value.publicKey.user.id
                || value.serverware?.authorizationMode !== 'oidc-session-first-enrollment'
                || value.publicKey.timeout !== 300000) throw new Error('First-key options do not match the source profile.');
            // A local refusal bound starting BEFORE issuance, never an extension
            // or substitute for the server's original ceremony expiration.
            owner.deadline = owner.started + value.publicKey.timeout;
            owner.check();
            owner.timer = setTimeout(() => {
              if (registrationCapture === owner) {
                registrationCaptureInvalidate('Original local capture bound elapsed.');
                renderRegistrationCapture();
              }
            }, Math.max(0, owner.deadline - performance.now()));
            owner.options = value;
            owner.phase = 'options-held';
            registrationCaptureMessage('Original first-key options held. Click Capture new hardware key separately before the original challenge expires.');
          } else {
            const fields = ['schema', 'status', 'purpose', 'localDigest', 'registrationCompleted', 'executionStarted'];
            if (!value || typeof value !== 'object' || Array.isArray(value)
                || Object.keys(value).sort().join(',') !== fields.sort().join(',')
                || value.schema !== 'serverware.webAuthnRegistrationExecutionPreparation/v1'
                || value.status !== 'retained-execution-grant' || value.purpose !== registrationCapturePurpose
                || !registrationHandoffDigest(value.localDigest)
                || value.registrationCompleted !== false || value.executionStarted !== false) {
              throw new Error('Preparation response is invalid or uncertain. No locator was accepted; inspect retained state.');
            }
            owner.check();
            $('registration-handoff-locator').value = value.localDigest;
            $('registration-handoff-mode').value = 'pending';
            clearRegistrationHandoffPrompt();
            clearTimeout(owner.timer);
            owner.attestation = null;
            registrationCapture = null;
            registrationCaptureMessage('Server returned a retained evidence-grant locator. Registration is NOT completed; execution has NOT started; session is NOT activated. Choose the next retained action separately.');
            renderRegistrationHandoff();
          }
        }
        return {uiHandled: true};
      } catch (_) {
        if (registrationCapture === owner) registrationCaptureInvalidate('First-key step cancelled, refused, changed or uncertain.');
        return {uiHandled: true};
      } finally {
        if (body) { delete body.bootstrapToken; delete body.response; }
        bootstrap = body = null; // Drop references, not a JavaScript zeroization claim.
        registrationCaptureBusy = oidcSessionActivationBusy = false;
        renderAuthStatus();
      }
    }

    function initRegistrationCapture() {
      for (const kind of ['options', 'hardware', 'prepare']) {
        $('registration-capture-' + kind).addEventListener('click', () => registrationCaptureAction(kind));
      }
      $('registration-capture-discard').addEventListener('click', () => {
        registrationCaptureInvalidate('Local first-key capture discarded.');
        renderRegistrationCapture();
      });
      window.addEventListener('pagehide', () => registrationCaptureInvalidate('Page closed.'));
      renderRegistrationCapture();
    }
"""

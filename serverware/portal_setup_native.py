"""Native Setup observation and protected enrollment UI; browser state grants no authority."""

from serverware.portal_setup_native_enrollment import (
    SETUP_NATIVE_ENROLLMENT_HTML,
    SETUP_NATIVE_ENROLLMENT_SCRIPT,
)
from serverware.portal_setup_native_ca import SETUP_NATIVE_CA_HTML, SETUP_NATIVE_CA_SCRIPT
from serverware.portal_setup_native_canary import SETUP_NATIVE_CANARY_HTML, SETUP_NATIVE_CANARY_SCRIPT

SETUP_NATIVE_POLICY_HTML = r"""
            <hr>
            <h4>Observe the native gate's loaded policy</h4>
            <p class="hint">This is separate from the control-plane loader. The actual Setup owner can request fresh native evidence for the retained policy, principal, route and credential association. The server checks the independently admitted native signer and quote; this page only displays its bounded result.</p>
            <button type="button" class="secondary" onclick="runUiAction('Observe native loaded policy', setupNativePolicyObserve)">Owner: request native loaded-policy observation</button>
            <pre id="setup-native-policy-observation">No native loaded-policy observation.</pre>
            <p id="setup-native-policy-status" class="hint" role="status" aria-live="polite">A matching policy is not proxy readiness, credential availability, installed client trust, enrollment or completed Setup. No policy reload or enrollment action is performed here.</p>
""" + SETUP_NATIVE_ENROLLMENT_HTML + SETUP_NATIVE_CA_HTML + SETUP_NATIVE_CANARY_HTML

SETUP_NATIVE_POLICY_SCRIPT = r"""
    function setupNativeOriginal(text, maximum) {
      setupPolicyNeed(typeof text === 'string' && text.length > 0 && /^[\x00-\x7f]*$/.test(text)
        && new TextEncoder().encode(text).length <= maximum);
      const value = oauthConsentParse(text, maximum).value;
      setupPolicyNeed(value && typeof value === 'object' && !Array.isArray(value)
        && oauthConsentCanonical(value) === text);
      return value;
    }
    async function setupNativePolicyObserve() {
      const operation = setupPolicyBegin();
      const output = $('setup-native-policy-observation'), status = $('setup-native-policy-status');
      try {
        output.textContent = 'No current native observation. Request in progress for Setup ' + operation.session + '.';
        status.textContent = 'One fresh, read-only observation; no policy reload, enrollment, automatic retry or provider request.';
        await oauthConsentCookie(operation);
        const value = await setupPolicyPost('/native-installed', {
          apiVersion: setupFileRequest, sessionId: operation.session, expectedRevision: 3,
        }, operation);
        setupPolicyNeed(oauthConsentClosed(value, ['apiVersion', 'okForAction', 'automaticRetryAllowed',
          'proxyReady', 'setupSessionId', 'observationOriginal'])
          && value.apiVersion === 'serverware.setupNativePolicyObservation/v1'
          && value.okForAction === false && value.automaticRetryAllowed === false && value.proxyReady === false
          && value.setupSessionId === operation.session);
        const observed = setupNativeOriginal(value.observationOriginal, 262144);
        setupPolicyNeed(oauthConsentClosed(observed, ['apiVersion', 'scope', 'okForAction', 'automaticRetryAllowed',
          'nativeLoadedPolicyVerified', 'proxyReady', 'continuationSha256', 'currentCredentialStateSha256',
          'requestOriginal', 'evidenceOriginal'])
          && observed.apiVersion === 'serverware.setupNativeLoadedPolicyObservation/v1'
          && observed.scope === 'native-loaded-policy-only' && observed.okForAction === false
          && observed.automaticRetryAllowed === false && observed.nativeLoadedPolicyVerified === true
          && observed.proxyReady === false && oauthConsentDigest(observed.continuationSha256)
          && oauthConsentDigest(observed.currentCredentialStateSha256));
        // These public originals are display data. The backend independently
        // verifies the native owner, signed request and original quote; parsing
        // them in a browser cannot confer that verification or action authority.
        setupNativeOriginal(observed.requestOriginal, 4096);
        setupNativeOriginal(observed.evidenceOriginal, 131072);
        operation.current();
        output.textContent = 'NATIVE LOADED POLICY ONLY — observed for Setup ' + value.setupSessionId
          + '. proxyReady: false.\n' + value.observationOriginal;
        status.textContent = 'The server verified native loaded-policy evidence for this observation. This does not prove client enrollment, CA installation, a working proxy request, canary readiness or completed Setup. Old materialization/recovery markers are unchanged.';
      } catch (error) {
        output.textContent = 'No current native loaded-policy observation was accepted for Setup ' + operation.session + '.';
        status.textContent = 'Refused, unavailable or uncertain. This is not proof that the gate is unloaded, and no policy reload, enrollment, marker clearing or automatic retry was authorized.';
        throw error;
      } finally { operation.close(); }
    }
""" + SETUP_NATIVE_ENROLLMENT_SCRIPT + SETUP_NATIVE_CA_SCRIPT + SETUP_NATIVE_CANARY_SCRIPT

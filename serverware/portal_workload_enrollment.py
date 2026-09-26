"""Read-only workload identity guidance inside the existing enrollment form.

The portal displays policy requirements, not certificate issuance, trusted TLS
evidence or enrollment readiness. The server remains the admission authority.
"""


WORKLOAD_ENROLLMENT_HTML = r"""
            <fieldset id="workload-enrollment-requirements" aria-describedby="workload-enrollment-boundary">
              <legend>Workload identity requirements</legend>
              <p id="workload-enrollment-boundary" class="hint">For applications, backend services, jobs and agents. These are current policy settings, not proof of certificate issuance, a verified connection or completed enrollment.</p>
              <div id="workload-enrollment-identity" role="status" aria-live="polite">Select a principal to view its public identity requirements.</div>
              <p id="workload-enrollment-https-warning" class="hint" role="alert" hidden></p>
              <p class="hint">When mTLS is configured, provision these separately through the approved enrollment and trust workflow:</p>
              <ul>
                <li><strong>Outer HTTPS proxy:</strong> a workload client certificate and private key, plus independently verified trust for the proxy's server certificate. Keep the private key with that workload; never paste it into this portal.</li>
                <li><strong>Inner provider-name HTTPS:</strong> the verifier-installed interception CA only. Do not attach the workload client key to provider-facing TLS or install an unverified CA globally.</li>
              </ul>
              <p class="hint">An HTTPS proxy environment variable alone does not configure client authentication. The client must support these two separate TLS roles. This form does not issue certificates, deliver private keys or change your proxy URL.</p>
            </fieldset>
"""


WORKLOAD_ENROLLMENT_SCRIPT = r"""
    function workloadEnrollmentPrincipal(principalId) {
      const principals = Array.isArray(state.policyPrincipals) ? state.policyPrincipals : [];
      return principals.find((item) => item && typeof item === 'object' && item.id === principalId) || null;
    }

    function assertWorkloadEnrollmentTransport(principalId, proxyUrl) {
      const principal = workloadEnrollmentPrincipal(principalId);
      if (!principal) throw new Error('Select a current policy principal before generating enrollment.');
      if (principal.mtlsConfigured !== true) return;
      const invalid = () => new Error('This principal requires an HTTPS proxy authority: https://host[:port], with no credentials, query, fragment or path other than /.');
      if (typeof proxyUrl !== 'string' || proxyUrl.length === 0 || proxyUrl.length > 4096
          || /[\s\\\u0000-\u001f\u007f-\u009f]/u.test(proxyUrl)) throw invalid();
      const prefix = /^https:\/\//i.exec(proxyUrl);
      if (!prefix) throw invalid();
      const remainder = proxyUrl.slice(prefix[0].length);
      const authority = remainder.split(/[/?#]/, 1)[0];
      const suffix = remainder.slice(authority.length);
      if (!authority || /[@%]/.test(authority) || (suffix !== '' && suffix !== '/')) throw invalid();
      let port = null;
      if (authority.startsWith('[')) {
        const match = /^\[[0-9a-fA-F:.]+\](?::([0-9]+))?$/.exec(authority);
        if (!match) throw invalid();
        port = match[1] ?? null;
      } else {
        const match = /^([^:]+)(?::([0-9]+))?$/.exec(authority);
        if (!match) throw invalid();
        port = match[2] ?? null;
      }
      // URL.port drops default ports and accepts some normalized spellings;
      // check the original port first, including empty/zero/leading-zero forms.
      if (port !== null && (!/^[1-9][0-9]{0,4}$/.test(port) || Number(port) > 65535)) throw invalid();
      let parsed;
      try { parsed = new URL(proxyUrl); } catch (_) { throw invalid(); }
      if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password
          || parsed.search || parsed.hash || parsed.pathname !== '/') throw invalid();
      // UI-only preflight: do not rewrite the input, resolve DNS or infer that
      // server-side policy, certificate, assignment or enrollment checks passed.
    }

    function workloadEnrollmentSelectorMarkup(mtls) {
      if (!mtls || typeof mtls !== 'object' || Array.isArray(mtls)
          || mtls.verifiedByTrustedIngress !== true) {
        return '<p class="hint">Public mTLS selector details are unavailable. Reload the policy summary; do not infer identity readiness.</p>';
      }
      const fields = [
        ['sanSpiffeIds', 'SPIFFE SAN'], ['sanDnsNames', 'DNS SAN'], ['sanUris', 'URI SAN'],
        ['certificateSha256', 'Leaf certificate SHA-256'], ['spkiSha256', 'Leaf SPKI SHA-256'],
        ['issuerSpkiSha256', 'Issuer SPKI SHA-256'],
      ];
      const rows = [];
      for (const [key, label] of fields) {
        if (!Object.prototype.hasOwnProperty.call(mtls, key)) continue;
        const value = mtls[key];
        if (key.startsWith('san')) {
          const limit = key === 'sanDnsNames' ? 253 : 2048;
          if (!Array.isArray(value) || value.length < 1 || value.length > 32
              || value.some((item) => typeof item !== 'string' || item.length < 1 || item.length > limit)) {
            return '<p class="hint">Public mTLS selector details are malformed. Reload the policy summary; server validation remains required.</p>';
          }
          rows.push(`<li>${esc(label)}: ${value.map((item) => `<code>${esc(item)}</code>`).join(', ')}</li>`);
        } else {
          if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(value)) {
            return '<p class="hint">Public mTLS selector details are malformed. Reload the policy summary; server validation remains required.</p>';
          }
          rows.push(`<li>${esc(label)}: <code>${esc(value)}</code></li>`);
        }
      }
      if (rows.length === 0) return '<p class="hint">No public mTLS selectors were returned. Reload the policy summary.</p>';
      return '<p>All configured selector fields are required; within each SAN list, one listed value must match.</p><ul>' + rows.join('') + '</ul>';
    }

    function renderWorkloadEnrollmentRequirements() {
      const select = $('enrollment-principal');
      const target = $('workload-enrollment-identity');
      const warning = $('workload-enrollment-https-warning');
      const proxy = $('enrollment-proxy-url');
      if (!select || !target || !warning || !proxy) return;
      const principal = workloadEnrollmentPrincipal(select.value);
      warning.hidden = true;
      warning.textContent = '';
      if (!principal) {
        target.textContent = 'Select a principal to view its public identity requirements.';
        return;
      }
      if (principal.mtlsConfigured !== true) {
        target.innerHTML = `<p><strong>${esc(principal.id)}</strong>: no mTLS selector is configured in this policy summary. Other identity and transport requirements still apply; this is not an enrollment readiness result.</p>`;
        return;
      }
      target.innerHTML = `<p><strong>${esc(principal.id)}</strong> requires workload authentication at the HTTPS proxy.</p>`
        + workloadEnrollmentSelectorMarkup(principal.mtls);
      warning.hidden = false;
      warning.textContent = 'HTTPS is required for this mTLS principal. Configure the outer client identity separately; this form does not provision it.';
      try {
        assertWorkloadEnrollmentTransport(select.value, proxy.value);
      } catch (error) {
        warning.textContent = error instanceof Error ? error.message : 'An explicit HTTPS proxy authority is required.';
      }
    }

    function initWorkloadEnrollmentRequirements() {
      const select = $('enrollment-principal');
      const proxy = $('enrollment-proxy-url');
      if (!select || !proxy) return;
      if (select.dataset.workloadRequirementsBound !== 'true') {
        select.addEventListener('change', renderWorkloadEnrollmentRequirements);
        select.dataset.workloadRequirementsBound = 'true';
      }
      if (proxy.dataset.workloadRequirementsBound !== 'true') {
        proxy.addEventListener('input', renderWorkloadEnrollmentRequirements);
        proxy.dataset.workloadRequirementsBound = 'true';
      }
      renderWorkloadEnrollmentRequirements();
    }
"""

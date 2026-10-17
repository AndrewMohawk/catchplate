"""Static portal fragments for public workload identity candidate authoring.

The server-side policy compiler and existing staged authority workflow remain
the authority. These strings never load keys, provision credentials or perform
TLS, enrollment or policy publication. The portal supplies the cloned bundle.
"""


WORKLOAD_IDENTITY_FORM_HTML = r"""
            <fieldset id="workload-identity-editor">
              <legend>Workload identity — apps, services, jobs, and agents</legend>
              <p class="hint">Author public client-certificate selectors only. Provision the client certificate and private key separately; never paste keys or provider credentials here. A policy preview is not a TLS handshake or enrollment.</p>
              <label for="workload-identity-mode">Identity change</label>
              <select id="workload-identity-mode" name="workloadIdentityMode">
                <option value="existing" selected>Use existing principal unchanged</option>
                <option value="create-mtls">Create a new mTLS workload principal</option>
                <option value="update-mtls">Update an existing mTLS principal's selectors</option>
              </select>
              <fieldset id="workload-new-principal-fields" hidden disabled>
                <legend>New workload principal</legend>
                <label for="workload-new-principal-id">Unique principal ID</label>
                <input id="workload-new-principal-id" name="workloadNewPrincipalId" maxlength="128" autocomplete="off" spellcheck="false" placeholder="service:billing-api" required>
                <p class="hint">1–128 characters; no wildcard, whitespace, or controls. The new principal contains only its ID and mTLS selectors.</p>
              </fieldset>
              <fieldset id="workload-mtls-selector-fields" hidden disabled>
                <legend>Trusted-ingress mTLS selectors</legend>
                <p class="hint">At least one SPIFFE ID, DNS SAN, URI SAN, leaf certificate hash, or leaf SPKI hash is required. Optional issuer SPKI alone is not sufficient. Each populated SAN list accepts 1–32 unique, canonical values, one per line. These are matching requirements, not proof that ingress verified a client.</p>
                <label for="workload-mtls-spiffe">SPIFFE SAN IDs</label>
                <textarea id="workload-mtls-spiffe" name="workloadMtlsSpiffe" maxlength="65568" spellcheck="false" placeholder="spiffe://example.invalid/services/billing"></textarea>
                <label for="workload-mtls-dns">DNS SAN names</label>
                <textarea id="workload-mtls-dns" name="workloadMtlsDns" maxlength="8160" spellcheck="false" placeholder="billing.example.invalid"></textarea>
                <label for="workload-mtls-uris">URI SAN values</label>
                <textarea id="workload-mtls-uris" name="workloadMtlsUris" maxlength="65568" spellcheck="false" placeholder="urn:example:workload:billing"></textarea>
                <label for="workload-mtls-certificate">Leaf certificate SHA-256 (optional)</label>
                <input id="workload-mtls-certificate" name="workloadMtlsCertificate" maxlength="71" spellcheck="false" placeholder="sha256: followed by 64 lowercase hexadecimal digits">
                <label for="workload-mtls-spki">Leaf SPKI SHA-256 (optional)</label>
                <input id="workload-mtls-spki" name="workloadMtlsSpki" maxlength="71" spellcheck="false" placeholder="sha256: followed by 64 lowercase hexadecimal digits">
                <label for="workload-mtls-issuer">Issuer SPKI SHA-256 (optional)</label>
                <input id="workload-mtls-issuer" name="workloadMtlsIssuer" maxlength="71" spellcheck="false" placeholder="sha256: followed by 64 lowercase hexadecimal digits">
              </fieldset>
              <fieldset id="workload-mtls-update-fields" hidden disabled>
                <legend>Existing mTLS identity update</legend>
                <button id="workload-mtls-load-current" type="button" class="secondary">Load selected principal's current selectors</button>
                <p class="hint">Loading replaces the selector draft. This mode cannot remove mTLS or upgrade a legacy principal; use a separately reviewed policy workflow for those changes. All other principal fields are preserved.</p>
                <label for="workload-mtls-confirm-all-routes">
                  <input id="workload-mtls-confirm-all-routes" name="workloadMtlsConfirmAllRoutes" type="checkbox" required>
                  I have reviewed this selector change for every route using the selected principal, not only the route being assigned.
                </label>
              </fieldset>
              <p id="workload-identity-status" class="hint" role="status" aria-live="polite"></p>
            </fieldset>
"""


WORKLOAD_IDENTITY_SCRIPT = r"""
    const workloadIdentityFields = Object.freeze({
      sanSpiffeIds: 'workload-mtls-spiffe',
      sanDnsNames: 'workload-mtls-dns',
      sanUris: 'workload-mtls-uris',
      certificateSha256: 'workload-mtls-certificate',
      spkiSha256: 'workload-mtls-spki',
      issuerSpkiSha256: 'workload-mtls-issuer'
    });
    let workloadIdentityEditorInitialized = false;
    let workloadIdentityLoadedPrincipal = null;
    // Python str.strip()/re whitespace, not JavaScript's different FEFF/0085
    // set: URI selector spelling must match the standalone shared validator.
    const workloadIdentityWhitespace = /[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]/u;

    function workloadIdentityByteLength(value) {
      for (const character of value) {
        const point = character.codePointAt(0);
        if (point >= 0xd800 && point <= 0xdfff) throw new Error('Workload identity text must be valid Unicode');
      }
      return new TextEncoder().encode(value).length;
    }

    function workloadIdentityPrincipals(bundle) {
      if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)
          || !Array.isArray(bundle.principals) || bundle.principals.length > 1024) {
        throw new Error('The policy principal inventory is unavailable or exceeds its bound');
      }
      const ids = new Set();
      for (const principal of bundle.principals) {
        if (!principal || typeof principal !== 'object' || Array.isArray(principal)
            || typeof principal.id !== 'string' || !principal.id || ids.has(principal.id)) {
          throw new Error('The policy principal inventory is malformed or ambiguous');
        }
        ids.add(principal.id);
      }
      return bundle.principals;
    }

    function workloadIdentitySelectedPrincipal() {
      const bundle = state.activePolicy?.bundle;
      const selected = $('policy-principal').value;
      if (!bundle || !Array.isArray(bundle.principals)) return null;
      const matches = bundle.principals.filter((item) => item && item.id === selected);
      return matches.length === 1 ? matches[0] : null;
    }

    function workloadIdentityHasMtls(principal) {
      return Boolean(principal && principal.mtls && typeof principal.mtls === 'object'
        && !Array.isArray(principal.mtls) && principal.mtls.verifiedByTrustedIngress === true);
    }

    function workloadIdentityValidateMtls(value) {
      // Match workload_transport.validate_mtls_identity and the policy compiler;
      // never silently rewrite SAN spellings or make a new trust decision here.
      const allowed = new Set(['verifiedByTrustedIngress', ...Object.keys(workloadIdentityFields)]);
      if (!value || typeof value !== 'object' || Array.isArray(value)
          || Object.keys(value).some((field) => !allowed.has(field))
          || value.verifiedByTrustedIngress !== true) {
        throw new Error('mTLS selectors must use the closed trusted-ingress identity schema');
      }
      const result = {verifiedByTrustedIngress: true};
      const lists = [
        ['sanSpiffeIds', /^spiffe:\/\/[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?(?:\/[A-Za-z0-9._~!$&'()*+,;=:@%-]+)*$/u, 2048],
        ['sanDnsNames', /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u, 253],
        ['sanUris', /^[a-z][a-z0-9+.-]*:[^\x00-\x20\x7f\x85\xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]{1,2040}$/u, 2048]
      ];
      for (const [field, pattern, maximum] of lists) {
        if (!Object.hasOwn(value, field)) continue;
        const items = value[field];
        if (!Array.isArray(items) || items.length < 1 || items.length > 32
            || new Set(items).size !== items.length) {
          throw new Error('Each populated SAN list requires 1–32 unique canonical values');
        }
        for (const item of items) {
          if (typeof item !== 'string' || !item
              || workloadIdentityWhitespace.test(item[0])
              || workloadIdentityWhitespace.test(item[item.length - 1])
              || item.length > maximum * 2 || workloadIdentityByteLength(item) > maximum
              || !pattern.test(item)) {
            throw new Error('A workload SAN selector is invalid or exceeds its byte bound');
          }
        }
        result[field] = [...items];
      }
      for (const field of ['certificateSha256', 'spkiSha256', 'issuerSpkiSha256']) {
        if (!Object.hasOwn(value, field)) continue;
        if (typeof value[field] !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value[field])
            || value[field].length !== 71) {
          throw new Error('Certificate and SPKI selectors require canonical lowercase SHA-256');
        }
        result[field] = value[field];
      }
      if (!['sanSpiffeIds', 'sanDnsNames', 'sanUris', 'certificateSha256', 'spkiSha256']
          .some((field) => Object.hasOwn(result, field))) {
        throw new Error('At least one SAN or leaf selector is required; issuer SPKI alone is insufficient');
      }
      return result;
    }

    function workloadIdentityReadSelectors() {
      const raw = {verifiedByTrustedIngress: true};
      for (const field of ['sanSpiffeIds', 'sanDnsNames', 'sanUris']) {
        const text = $(workloadIdentityFields[field]).value;
        const maximum = field === 'sanDnsNames' ? 8160 : 65568;
        if (text.length > maximum) throw new Error('The workload SAN list exceeds its input bound');
        const lines = text.split(/\r?\n/u).filter((line) => line !== '');
        if (lines.length) raw[field] = lines;
      }
      for (const field of ['certificateSha256', 'spkiSha256', 'issuerSpkiSha256']) {
        const text = $(workloadIdentityFields[field]).value;
        if (text !== '') raw[field] = text;
      }
      return workloadIdentityValidateMtls(raw);
    }

    function workloadIdentityLoadSelected() {
      invalidatePolicyCandidate();
      workloadIdentityLoadedPrincipal = null;
      $('workload-mtls-confirm-all-routes').checked = false;
      try {
        const principal = workloadIdentitySelectedPrincipal();
        if ($('workload-identity-mode').value !== 'update-mtls' || !workloadIdentityHasMtls(principal)) {
          throw new Error('Select an already configured mTLS principal; legacy upgrades are not supported here');
        }
        const selectors = workloadIdentityValidateMtls(principal.mtls);
        for (const [field, id] of Object.entries(workloadIdentityFields)) {
          $(id).value = Array.isArray(selectors[field]) ? selectors[field].join('\n') : selectors[field] || '';
        }
        workloadIdentityLoadedPrincipal = principal.id;
      } finally {
        renderWorkloadIdentityEditor();
      }
    }

    function buildWorkloadPrincipalDraft(bundle, selectedPrincipalId) {
      const principals = workloadIdentityPrincipals(bundle);
      const mode = $('workload-identity-mode').value;
      if (!['existing', 'create-mtls', 'update-mtls'].includes(mode)) {
        throw new Error('Select a supported workload identity mode');
      }
      if (mode === 'existing') {
        if (!principals.some((item) => item.id === selectedPrincipalId)) {
          throw new Error('Select an existing policy principal');
        }
        return {principalId: selectedPrincipalId, changeSummary: `Use existing principal ${selectedPrincipalId}; identity unchanged.`};
      }
      if (mode === 'create-mtls') {
        const principalId = $('workload-new-principal-id').value;
        if (!principalId || [...principalId].length > 128 || principalId !== principalId.trim()
            || /[\s*\x00-\x1f\x7f-\x9f]/u.test(principalId)
            || workloadIdentityByteLength(principalId) > 512) {
          throw new Error('New principal ID must be 1–128 characters without wildcard, whitespace or controls');
        }
        if (principals.some((item) => item.id === principalId)) throw new Error('New workload principal ID already exists');
        if (principals.length >= 1024) throw new Error('The policy principal inventory is full');
        const mtls = workloadIdentityReadSelectors();
        principals.push({id: principalId, mtls});
        return {principalId, changeSummary: `Create mTLS workload principal ${principalId}; client credentials must be provisioned separately.`};
      }
      const principal = principals.find((item) => item.id === selectedPrincipalId);
      if (!workloadIdentityHasMtls(principal)) {
        throw new Error('Only an existing configured mTLS principal can be updated in this mode');
      }
      if (workloadIdentityLoadedPrincipal !== selectedPrincipalId) {
        throw new Error('Load the selected principal’s current selectors before preparing an update');
      }
      if (!$('workload-mtls-confirm-all-routes').checked) {
        throw new Error('Explicitly review the selector change for every route using this principal');
      }
      const mtls = workloadIdentityReadSelectors();
      // The caller supplied a clone. Preserve every other existing principal
      // property, including source CIDRs, required headers and authorization.
      principal.mtls = mtls;
      return {principalId: selectedPrincipalId, changeSummary: `Update mTLS selectors for ${selectedPrincipalId}; affects every route using this principal. Other principal fields are unchanged.`};
    }

    function renderWorkloadIdentityEditor() {
      // Refresh calls this after restoring controls. Never assign draft values
      // here; periodic refresh is not consent to reload or reset an identity.
      const mode = $('workload-identity-mode').value;
      const creating = mode === 'create-mtls';
      const updating = mode === 'update-mtls';
      for (const [id, shown] of [
        ['workload-new-principal-fields', creating],
        ['workload-mtls-selector-fields', creating || updating],
        ['workload-mtls-update-fields', updating]
      ]) {
        $(id).hidden = !shown;
        $(id).disabled = !shown;
      }
      const principal = workloadIdentitySelectedPrincipal();
      let message = 'Use the selected principal without changing any identity requirements.';
      if (creating) message = 'A new mTLS-only principal will be added to the candidate for this route; no client key or provider credential is created.';
      if (updating) {
        message = !workloadIdentityHasMtls(principal)
          ? 'The selection is not an existing mTLS principal. Choose one; this editor cannot upgrade legacy identity or remove mTLS.'
          : workloadIdentityLoadedPrincipal !== principal.id
            ? 'Load the selected principal’s current selectors before preparing an all-routes update.'
            : 'Selector draft retained. Updating this principal affects every route that uses it; review and acknowledge that scope.';
      }
      $('workload-identity-status').textContent = message;
    }

    function initWorkloadIdentityEditor() {
      if (workloadIdentityEditorInitialized) return;
      workloadIdentityEditorInitialized = true;
      const editor = $('workload-identity-editor');
      const invalidate = (event) => {
        invalidatePolicyCandidate();
        if (event.target.id !== 'workload-mtls-confirm-all-routes') {
          $('workload-mtls-confirm-all-routes').checked = false;
        }
      };
      editor.addEventListener('input', invalidate);
      editor.addEventListener('change', invalidate);
      $('workload-identity-mode').addEventListener('change', () => {
        workloadIdentityLoadedPrincipal = null;
        $('workload-mtls-confirm-all-routes').checked = false;
        if ($('workload-identity-mode').value === 'update-mtls') {
          runUiAction('Load current workload identity', workloadIdentityLoadSelected);
        } else {
          renderWorkloadIdentityEditor();
        }
      });
      $('policy-principal').addEventListener('change', () => {
        invalidatePolicyCandidate();
        workloadIdentityLoadedPrincipal = null;
        $('workload-mtls-confirm-all-routes').checked = false;
        if ($('workload-identity-mode').value === 'update-mtls') {
          runUiAction('Load current workload identity', workloadIdentityLoadSelected);
        } else {
          renderWorkloadIdentityEditor();
        }
      });
      $('workload-mtls-load-current').addEventListener('click', () => {
        runUiAction('Load current workload identity', workloadIdentityLoadSelected);
      });
      renderWorkloadIdentityEditor();
    }
"""

# Explicit native workload issuance submission

The native SDK and CLI connect request-first target originals to the existing
cookie-authenticated workload issuance action. This is source-connected code,
not a build, deployment, issuance, mTLS handshake or production acceptance result.
Legacy packet-bound submission APIs and CLI modes remain unchanged.

## Independently provisioned prerequisites

The operator must separately provision the [native runtime and setup authority](native-enrollment-bootstrap-setup.md),
an already authenticated bootstrap caller, current policy and independent
delegation/setup roots, and the [native issuer cold profile](native-workload-identity-issuer-bootstrap.md).
The public caller must have its separately signed native caller-v2 configuration;
the HTTP body cannot select or enable a native profile. The CA key and dedicated
grant-authorizer key are not supplied to this CLI. The signed per-request
[native issuance grant](native-workload-identity-issuance-authorization.md) must be
obtained independently; a packet, CSR, role-3/role-5 capture, browser assertion or
data-only extraction cannot mint it.

The operator endpoint requires a current cookie session and CSRF value, a requester
with the `policy_author` role, fresh genuine WebAuthn, and a different authorized
approver. The existing mandatory two-person flow is not bypassed by native inputs.
The SDK pins the exact HTTPS origin, literal connection IP/port, TLS server name,
CA file and leaf SPKI, plus protected cookie/CSRF files. There are no bearer,
environment-default, proxy, redirect or alternative-endpoint fallbacks.

## Practical order

1. Use `--prepare-workload-bootstrap` to create the target's retained P-256 key,
   canonical CSR and signed request from an independently pinned issuer, expected
   principal/nonce and explicit SANs. Retain the original private key locally.
   No previous target certificate or legacy enrollment packet is required.
2. Obtain the independently authorized delegation/setup and use the
   [fixed native bootstrap client](native-bootstrap-client.md) to acquire its
   public capture. Its diagnostic output is not CA or installation permission.
3. Use `--extract-native-bootstrap-packet` with `--workload-capture` and
   `--workload-capture-sha256`, the exact `--workload-request` and
   `--workload-request-sha256`, and `--workload-output-directory`. The optional
   `--workload-timeout-ms` is the only other accepted flag. This local, network-free
   [extractor](native-bootstrap-capture.md) publishes exact `native-packet.json`
   bytes and a public pin after matching the embedded target request. It does not
   verify quotes, signatures or authority; its result explicitly keeps
   `okForAction`, `issuanceAuthorized`, `proxyAuthenticated` and
   `enrollmentComplete` false.
4. Obtain the separate signed native issuance grant for those exact packet,
   request, issuer, principal/nonce and selected SAN originals. The server will
   genuinely re-admit its signatures and cold scope; the SDK's pinned-grant
   comparisons only select the exact requested association.
5. Invoke `--request-native-workload-issuance-options` with the common inputs
   below and a fresh protected output directory. This makes one options POST,
   never an issuance request or CA-worker contact, and retains
   `options-response.json`. Use the existing same-origin portal
   [options-import/passkey/assertion-download flow](workload-identity-submission.md)
   to perform a fresh ceremony. Protect and independently pin the raw assertion
   file; the browser does not export cookies or private keys in that file.
6. Invoke `--submit-native-workload-issuance` with the identical public originals,
   protected options/assertion pins, the retained target private-key pin and a
   new attempt directory. The key is genuinely loaded and joined to the request
   before any POST. An irreversible local `submission.claim` is published before
   contact; the HTTP owner also spends its single connection permission before
   connecting or sending.
7. Only an exact retained `approval-required` HTTP 428 permits a deliberate
   continuation. A different operator must approve using their own fresh WebAuthn.
   The requester then obtains new options and a new assertion and explicitly
   submits the same originals from another directory, supplying the prior 428
   receipt with `--workload-approval` and `--workload-approval-sha256`. There is
   no automatic 428/412 resubmit. Unknown or interrupted outcomes never permit
   retry, deletion of the claim or inferred nonissuance.
8. On an exact `certificate-issued` response, the SDK admits the real leaf against
   its independent issuer, canonical request, exact SANs and retained key before
   publishing `client-certificate.pem`. The response, intermediate public leaf
   and final leaf-plus-issuer chain are retained with protected no-overwrite
   publication and readback. This does not install trust or prove proxy use.

Each stage preserves its inputs' original signed expiry. Fresh options or another
directory do not extend the target's issuer-clipped five-minute request or grant.
The server separately enforces the original challenge lifetime and current session.
If those intervals expire during human approval, stop; do not reinterpret an old
claim, receipt or unknown outcome as permission to retry.

## Browser issuance and local certificate admission

The portal's **Issue a workload certificate** workspace now has an explicit
**Native request-first bootstrap** file format. Use the same independently
provisioned issuer and originals from steps 1–4 above; the browser is an
alternative to the CLI options/submission steps, not another issuance attempt.

Select the signed native grant, the exact extracted native packet v2 and its
original signed target bootstrap request. The portal checks their schemas,
original-byte pins and matching target request before requesting options. It
preserves native principal spelling and the 1024-byte UTF-8 bound, without
normalization or a legacy packet/signing-key alias. Grant/packet/request ceilings
are 32/512/64 KiB, inside the existing 3 MiB encoded request limit.

The selector changes local checks only. It is not transmitted as authority:
the server's independently provisioned cold owner selects the actual verifier
and re-admits the signatures and all originals. The existing OIDC cookie/CSRF,
fresh requester passkey, distinct approver and explicit fresh-passkey continuation
remain mandatory. Switching format discards selected files, pending continuation
and downloadable results without clearing attempt locks or unknown outcomes.

After a matching certificate response, the portal displays its exact SHA-256
and offers the public leaf for download. On the workload host, invoke
`serverware-enrollment --admit-native-workload-certificate` with:

- `--workload-packet`, `--workload-issuer`, `--workload-request`,
  `--workload-private-key` and `--workload-certificate`, each with its matching
  `-sha256` pin. Keep the originally retained private key on this host.
- The independent `--expected-principal`, `--expected-nonce` and repeated
  `--workload-san-dns` and/or `--workload-san-uri` values used for preparation.
  At least one SAN is required; duplicates are refused.
- `--workload-output-directory`, an existing current-user-owned mode-0700
  directory with no previous destination, and optional `--workload-timeout-ms`.

This command calls the existing [native retained-key verifier](native-workload-identity-provisioning.md).
It verifies the actual issuer signature, request/key/SAN association and original
validity, then publishes `client-certificate.pem` as a protected leaf-plus-issuer
chain without replacing any identity. It cannot contact an issuer, create a key,
install trust or finish Setup. Standalone admission does not claim to verify the
separate issuance grant's chosen serial/dates; the CLI submission lane above
also checks that grant association. Missing or late results do not permit retry.

The separate CLI options-receipt/passkey bridge works with both native and legacy
receipts because the action and endpoint are unchanged. Import never submits
issuance; download never renews the server's original challenge lifetime.

## Explicit CLI and SDK inputs

Native options and submission share:

- `--workload-packet`, `--workload-issuer`, `--workload-authorization`,
  `--workload-request`, `--workload-tls-ca`, `--workload-cookie` and
  `--workload-csrf`, each with its matching `-sha256` pin.
- `--expected-principal`, `--expected-nonce`, repeated `--workload-san-dns`
  and/or `--workload-san-uri`. At least one SAN is required; duplicates refuse,
  and the two arrays are sorted independently. The native principal retains the
  original UTF-8 profile, up to 1024 bytes, not the legacy 512-byte text limit.
- `--workload-origin`, `--workload-endpoint-address`, `--workload-endpoint-port`,
  `--workload-server-name`, `--workload-server-spki-sha256`,
  `--workload-output-directory`, and optional `--workload-timeout-ms` (100–30000).

Submission additionally requires `--workload-private-key`, `--workload-options`
and `--workload-assertion`, each with its `-sha256` pin. Options-only mode refuses
these and approval inputs. Neither native mode accepts `--workload-packet-signing-key`,
legacy enrollment/receipt options or a fabricated runtime-manifest identity.

`serverware_agent_trust.native_workload_identity_submission` exports
`request_issuance_options(...)` and `submit_issuance(...)`. Both accept the existing
`OperatorEndpoint`, pinned `packet`, `issuer`, `authorization` and `request`,
`expected_principal`, `expected_nonce`, explicit `requested_sans`,
`output_directory` and optional `timeout_ms`. Submission also accepts pinned
`private_key`, `options`, `assertion` and optional exact 428 `approval` receipt.
There is no `packet_signing_key` argument or `serverware` import.

## Bounds, retained outcomes and authority boundary

One original `Budget` and descriptor owner cover all input reads, TLS, the single
HTTP request, leaf checks and protected publication. Native packet/grant/request
caps are 512/32/64 KiB; options/assertion bodies are at most 32 KiB, protected
response receipts at most 192 KiB, and HTTP response bodies at most 128 KiB.
Before bodies are loaded, the native lane reserves fixed transport/publication
space plus sixteen representations of held inputs and the maximum HTTP body
inside the same 64 MiB ceiling. No stage renews that budget. Published files use
the existing current-owner 0700 directory and exclusive 0600 file profile.

The action remains `workload.identity.issue` at the existing `/issue/options`
and `/issue` paths under `/api/agents/workload-identity`. The exact grant, packet
and request digests, principal/nonce, cold bootstrap/configuration, actual issuer
PEM digest and grant ID bind fresh WebAuthn and approval. The grant's distinct
issuer DER digest is also joined to the real local issuer; it is never used as
an alias for the PEM file pin.

CLI exit codes are 0 for options/certificate success, 3 for retained approval
required, 4 for a retained explicit unknown outcome and 5 for a retained refusal.
A transport or verification exception is unconfirmed, not an implicit refusal;
preserve all artifacts and do not retry. These directories are per-attempt state,
not a global deduplication or cross-session recovery service.

Public submission output contains status and protected-file pins, with
`proxyAuthenticated`, `enrollmentComplete` and `automaticRetryAllowed` false.
The [retained-key leaf admission](native-workload-identity-provisioning.md)
establishes certificate/key compatibility, not full runtime-policy authentication,
CA installation, protected token/namespace ownership, egress-canary success,
issuer rotation/revocation, off-host rollback protection or production acceptance.

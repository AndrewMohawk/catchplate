# Request-first workload identity bootstrap preparation

Status: source-only, unbuilt and unexecuted. This profile prepares a fresh target
key, CSR and same-key possession request **without an enrollment packet or an
existing target certificate**. It supplies neither an authenticated bootstrap
caller nor delegation, packet issuance, CA permission or completed onboarding.
Native signing and the enrollment request route remain inaccessible; no parent
checkpoint, tested pilot or production acceptance is claimed.

## Target possession, not authority

The [existing-identity native gate](native-enrollment-admission.md#existing-identity-is-not-first-time-bootstrap)
requires an already authenticated client certificate. The older
[packet-bound preparation](workload-identity-provisioning.md) requires a signed
packet before generating its CSR. Those prerequisites cannot define first-time
onboarding if the target needs its first certificate to obtain that same packet.

This explicit request-first profile removes the packet/certificate prerequisite
from **local target-key preparation only**. A target's self-signature can prove
possession of a requested key; it cannot establish entitlement to the requested
principal, SANs, issuer or lifetime. Matching an independently supplied issuer
pin authenticates that selected public original, not a CA issuance permission.

The next authority contract remains separate: an explicit caller-to-target
delegation purpose from the independently pinned enrollment-authorizer origin,
with genuine bootstrap-caller/principal admission and original target grant/CSR
possession. The independent issuer grant remains mandatory. Neither a successful
request-verifier result nor a CA-install capability can replace those authorities.

## Closed original request

The [request schema](../schemas/workload-identity-bootstrap-request.v1.schema.json)
is exactly `{schema, payload, signature}`. The envelope schema is
`serverware.signedWorkloadIdentityBootstrapRequest/v1`; the payload schema is
`serverware.workloadIdentityBootstrapRequest/v1`. Its ten fields bind the target
principal and nonce, issuer certificate DER/SPKI, target SPKI, requested SANs,
creation/expiry and exact CSR PEM plus digest. There is no packet digest, target
certificate, caller identity, delegation or `runtimeManifestDigest` field.

The request uses existing compact sorted canonical JSON, **without a final LF**,
at most 64 KiB. The CSR is canonical PEM at most 16 KiB, with an empty subject,
genuine P-256/SHA-256 signature and the fixed critical SAN-only extension profile.
`requestedSans` is exactly `{dnsNames, uris}`: each list is sorted and unique,
with 1–8 entries total and at most 8 KiB of combined UTF-8 SAN text. DNS and URI
spellings retain the existing strict validators; certificate order is DNS then URI.

The same target key signs:

```text
ASCII("serverware.workloadIdentityBootstrapRequest/v1") || NUL
    || canonical payload JSON bytes
```

`signature` is `ecdsa-p256-sha256:` followed by canonical unpadded base64url DER
ECDSA `(r,s)`, with low-S enforced. The verifier checks both the genuine CSR
signature and this separate request signature; hashes or schema shape alone do
not prove possession.

The issuer path's external file pin hashes its exact PEM original. In contrast,
`issuerCertificateDerSha256` hashes the parsed certificate DER,
`issuerSpkiSha256` and `subjectPublicKeyInfoSha256` hash their respective DER
SPKIs, and `csr.sha256` hashes the exact canonical CSR PEM. These byte domains
are not interchangeable.

The self-asserted request interval must be current, positive, no longer than
300,000 ms, and wholly within issuer validity. Epoch milliseconds are capped at
9,223,372,036,854 for signed-64-bit nanosecond representation. Independent caller
delegation and issuer authorization must still impose their own valid intervals;
request timestamps cannot renew them.

## Local SDK and CLI

`workload_identity_bootstrap.prepare_bootstrap(issuer=..., expected_principal=...,
expected_nonce=..., requested_sans={"dnsNames": [...], "uris": [...]},
output_directory=..., timeout_ms=30000)` takes an independently pinned issuer
`PinnedFile` and returns `PreparedIdentity(request, csr, private_key)` file pins.
The explicit principal, nonce and SANs are expectations for the original verifier,
not authorization derived from the self-signed request.

The existing output directory must belong to the current user and have mode
0700. A sticky `preparation.claim`, using a distinct bootstrap claim schema, is
published before key generation. The fixed outputs are `private-key.pem`,
`request.pem` and `request.json`, exclusively published as mode 0600 without
overwrite, fsynced and read back under retained original guards. Partial artifacts
remain on uncertainty; preparation must not be retried in that directory. The
private key is local software-held PKCS8, not HSM custody or an erasure guarantee.

`workload_identity_bootstrap_originals.verify_request_on_budget` takes request
and issuer bytes plus independent expected principal, nonce and SANs on the
caller's existing budget. It creates no replacement allowance. Local preparation
genuinely verifies the request before publication and return. The original local
timeout is 100–30,000 ms, defaulting
to 30,000; request expiry is the earlier of creation plus five minutes and actual
issuer expiry. No TTL override or clock renewal is exposed.

The mutually exclusive local CLI mode is `--prepare-workload-bootstrap`. Its
only inputs are:

- `--workload-issuer` and `--workload-issuer-sha256`;
- `--expected-principal` and `--expected-nonce`;
- repeatable `--workload-san-dns` and `--workload-san-uri`;
- `--workload-output-directory` and optional `--workload-timeout-ms`.

The CLI sorts each SAN list and rejects duplicates. Packet, administration,
ordinary networking and certificate-admission options cannot be mixed into this
mode; inherited enrollment environment defaults are not used as authority.
There is no network contact, certificate issuance, trust installation or automatic
submission. Public output uses `serverware.workloadIdentityLocalResult/v1`, profile
`request-first-p256-bootstrap-v1` and status `bootstrap-prepared-local-only`.
It contains artifact pins, never private-key contents; `issuanceAuthorized`,
`proxyAuthenticated` and `enrollmentComplete` stay false.

## Remaining bootstrap integration

The current issuer and packet-bound admission paths still accept their existing
v1 contracts, not this bootstrap request as a replacement. Do not submit it to an
old route using a relabeled schema or treat legacy `runtimeManifestDigest` as a
native runtime-scope hash. The legacy operator packet route still refuses
production attestation; it is not a bootstrap fallback.

Independent caller-to-target delegation, genuine caller acquisition, separate
issuer authorization, actual packet/SDK/issuer integration and durable one-use
claim/recovery remain required. Target CSR possession does not authorize signing
an enrollment packet or a certificate. Scoped installation, proxy/egress and
allow/deny canaries remain separate, with production acceptance **0/6 verified**.

Future verification must cover exact schema/domain separation, altered keys/CSRs,
wrong issuer/principal/nonce/SANs, low-S and canonical-encoding rejection, interval
and issuer boundaries, retained-file changes, partial publication and refusal of
mixed CLI modes or retries. These are future checks, not test results. No tests,
builds, imports, parser/interpreter execution, runtime, browser, network, NSM or
AWS/spend actions were used for this source increment.

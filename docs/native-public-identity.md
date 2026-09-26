# Native startup public identity export

Status: source-only, unbuilt and unexecuted. Native startup can optionally emit
the actual generated ingress certificate chain and its original role-3 NSM
quote. This is public bootstrap material for separate verification, not a
trusted CA installation, readiness receipt or production attestation result.

## Opt-in transfer, before listening

Add the valueless `--public-identity-stdout` option once to the
[native startup command](native-startup-config.md#exact-command-selection).
The four configuration/launch path and digest options remain required. There
is no environment fallback or export from the legacy no-argument path.

After actual native gate preparation succeeds, but **before** binding the
vsock listener, the [startup emitter](../data-plane/decision-gate-rs/src/native_public_identity.rs)
writes one compact JSON object followed by one LF to stdout. The complete line
is at most 65,536 bytes. The source checks the actual retained state, CA,
ingress and original lifetime around this transfer; it does
not recreate keys, renew the quote or extend the launch deadline. With the flag
absent, startup does not emit this public identity line.

The write can block in the operating system. A write or flush failure aborts
startup and can leave partial output; do not treat a partial line as evidence.
A complete line also does not
prove that the later bind, runtime readiness or serving succeeded. Capturing
stdout is a caller-owned transfer, not a protected file publisher, immutable
archive, trust-store installer or hard watchdog. Do not mix diagnostics or
unrelated output into the retained original.

## Exact public object

The top-level fields are:

| Field | Value |
| --- | --- |
| `apiVersion` | `serverware.nativeIngressPublicEvidence/v1` |
| `evidenceScope` | `unverified-startup-public-material` |
| `okForAction` | `false` |
| `ingress` | The actual public TLS configuration below. |
| `quote` | The unchanged startup quote originals below. |

`ingress` contains exactly:

- `tlsProtocol`: `TLSv1.3`;
- `clientAuthentication`: `mandatory-webpki`;
- `certificateChainDerBase64url`: the actual leaf and CA DER, in that order;
- `leafPublicKeySpkiDerBase64url`: the actual outer leaf SPKI DER;
- `clientTrustBundleSha256`: the exact length-framed installed client-root
  commitment described in [runtime identity](enclave-runtime-identity.md).

`quote` contains `documentBase64url`, `userDataBase64url`,
`publicKeyBase64url` and `nonceBase64url`. Byte fields use canonical URL-safe
base64 without padding. They retain the original NSM document, exact role-3
binary binding, quoted leaf SPKI and startup nonce, not a copied verifier
verdict or freshly fabricated claims.

The [encoder](../data-plane/decision-gate-rs/src/enclave_public_identity_v1.rs)
bounds each leaf/CA DER to 1–16 KiB, each SPKI to 1–1,024 bytes,
and the original quote document to 1–12,288 bytes. User data is the exact
runtime-key-binding domain, role byte `3` and seven 32-byte fields; the nonce
is exactly 32 bytes. Full-line size can reject an otherwise individually
bounded set. The export contains no private key, client-root DER inventory,
service bearer token or configuration original.

Certificate validity, actual key/CA equality and binary binding checks establish
local consistency with retained owners. They do not verify the Nitro vendor
chain, COSE signature, PCRs, release provenance or current authority. The
role-3 binding commits to release/policy/configuration references, actual CA
certificate/SPKI, actual leaf SPKI, leaf DER and installed client-root
commitment. Matching supplied references does not authenticate their origin.

## Verification and enrollment remain separate

```text
actual prepared native owners
    -> public originals on stdout (unverified, not ready)
    -> independently configured verifier + fresh client/session evidence
    -> separately authorized, agent-scoped CA installation
```

The exported nonce is the **launch nonce**, not a challenge obtained from a
client/verifier exchange. The object has no live TLS exporter, exact client
request/response binding, nonce reservation, latest witness state or one-use
acceptance. It is not `serverware.productionAttestation/v2`, an enrollment
packet, the native response-capture artifact or a success token accepted by
those consumers. No automatic enrollment or existing-verifier compatibility
is claimed.

The [production trust flow](../goal.md#attestation-goal) requires a fresh
client-held 32-byte challenge over the actual enclave-owned TLS session,
exporter/request/signed-scope binding, genuine Nitro verification against
independent roots and release/PCR expectations, and exact certificate/SPKI
joins. Independent reproducible release/policy/configuration admission,
enclave/KMS Recipient custody, trusted time, current off-host
witness/CAS/revocation state and one-use challenge handling remain required.
Stored verification and completion do not themselves authorize an action.

The [enrollment flow](portal-oauth-agent-guide.md#teach-agents-to-use-serverware)
separately authenticates exact packet bytes, principal, challenge, validity,
measurements and signature before scoped CA retrieval. Direct CA installation
from this stdout object would bypass that requirement. The only supported
production installation is verifier-mediated and limited to the agent runtime;
exporting public certificate bytes does not authorize trusting them.

The [parent ingress](native-parent-ingress.md) remains an opaque transport.
This export adds no HTTP management endpoint, TLS bypass, PROXY header or
parent/client-IP authority. Mandatory client-certificate verification stays
inside the enclave. Independent provisioning, nonce delivery, verified
bootstrap/enrollment and the [production acceptance gates](security-review.md#production-acceptance-gates)
are not supplied here. No build, test, runtime, hardware or deployment evidence
was produced for this source slice.

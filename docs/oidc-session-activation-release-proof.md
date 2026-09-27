# Private committed-release proof wire

This source-only contract is unbuilt, unexecuted and unprovisioned. It binds
token-free claims in a distinct signature domain; parsing or signing a payload
does not establish committed consumption, release permission or plaintext
delivery. It adds no generic operation or public endpoint.

The fixed purpose is `prove-oidc-session-activation-committed-release`. The
envelope schema and signature domain are
`serverware.signedOidcSessionActivationReleaseProof/v1`; the payload schema is
`serverware.oidcSessionActivationReleaseProof/v1`. Exact canonical proof bytes
have identity domain `serverware.oidcSessionActivationReleaseProofIdentity/v1`.
The separate `serverware.oidcSessionActivationReleaseProofCustodyIdentity/v1`
domain is exported for the actual consumer to identify original release custody;
it is not the proof signature domain or admission of those custody bytes.

The envelope has exactly `schema`, `payload` and `signatureBase64Url`. Its closed
23-field payload contains:

- `schema`, `sourceRevision`, `purpose`, `enrollmentDigest` and
  `producerMeasurementDigest`;
- the seven independently scoped enrollment fields: `configurationDigest`,
  `databaseId`, `generationDigest`, `runtimeClosureDigest`, `producerId`,
  `producerIdentity` and `receiverIdentity`;
- the six release fields: `activationRequestDigest`, `activationOperationId`,
  `consumeRequestDigest`, `deliveryEnvelopeDigest`, `deliveryScope` and
  `consumeBinding`;
- `releaseCustodyDigest`, `releaseIntentDigest`, `stateReceiptDigest`,
  `issuedAtEpochNs` and `expiresAtEpochNs`.

Both identities use the existing exact three-digest shape.
`producerMeasurementDigest` must equal `producerIdentity.measurementDigest`;
neither value proves measured execution. `deliveryScope` reuses the actual
eleven-field [release-custody grammar](oidc-session-activation-release-custody.md),
including credential encoding, token rotation and original delivery lifetime.
`consumeBinding` is exactly `packetDigest`, `pendingDecisionDigest`,
`completionRequestDigest`, `effectsDigest` and `afterVectorDigest`. These are
claims to compare against genuine originals, not substitutes for those originals.

The positive proof interval is bounded by `VERIFIER_RESPONSE_MAX_AGE_NS` and
cannot expire after the original delivery. Actual production and admission must
also preserve the fresh intent, enrolled policy and supplied current processing
window. The wire opens no clock or work allowance. There is no nonce,
`tokenReleased` flag, plaintext, token, private key or durable one-use claim.

```text
_capture(value, work) -> owned bounded ordinary data
_read(original, work) -> owned canonical signed-envelope dictionary
_digest(original, work) -> exact-original domain-framed identity
_signature(envelope, public_key, work) -> None
_sign(payload, *, private_key, public_key, work) -> original bytes
```

The complete envelope is bounded at 64 KiB, 256 JSON nodes and depth four.
Capture, canonical decoding/comparison, framing and Ed25519 operations charge
the same cumulative work. Mutable input is owned before native key callbacks;
signing checks the actual key pair, reserves the complete output, verifies the
generated signature and reads back the exact canonical payload.

`_read` and `_digest` do not authenticate. `_signature` checks only the fixed
proof signature under the supplied actual key. `_sign` is a private primitive,
not an endpoint that accepts posted claims as authority. The distinct
[root enrollment](oidc-session-activation-release-proof-enrollment.md), actual
[committed-original admission](oidc-session-activation-release-committed.md),
producer and independent receiver must supply the genuine authority joins.
Durable release outcomes, guarded token opening, recovery, cold handoff and
later public permission remain separate gates; this wire closes none of them.

# Committed-release proof producer enrollment

This distinct root-signed enrollment binds the actual proof key to independently
held producer, receiver and configuration scope. It is source-only, unbuilt,
unexecuted and unprovisioned; enrollment does not prove committed consumption or
authorize token disclosure.

The purpose is `enroll-oidc-session-activation-committed-release-producer`. The
envelope schema and signature domain are
`catchplate.signedOidcSessionActivationReleaseProofEnrollment/v1`. The payload
schema is `catchplate.oidcSessionActivationReleaseProofEnrollment/v1`; exact
original identity uses
`catchplate.oidcSessionActivationReleaseProofEnrollmentIdentity/v1`.

The closed payload contains `schema`, `sourceRevision`, `purpose`, seven scope
fields, `proofKey`, `maximumAgeNs` and `maximumClockSkewNs`. Scope is exactly
`configurationDigest`, `databaseId`, `generationDigest`, `runtimeClosureDigest`,
`producerId`, `producerIdentity` and `receiverIdentity`. Both identities use the
existing exact three-digest grammar. `proofKey` contains only canonical
`publicKeyPem`, `spkiDigest` and `measurementDigest`; its measurement must equal
the independently scoped producer identity's measurement. These are signed
identity assertions, not hardware or measured-runtime evidence.

```text
_scope(value, work) -> owned scope7
_forbidden(values) -> bounded tuple of actual independent public keys
_admit_on_work(*, enrollment_bytes, root_public_key, expected_scope,
               forbidden_public_keys, work)
  -> _Enrollment(payload, enrollment_digest, proof_public_key)
_produce_on_work(*, payload, root_private_key, root_public_key,
                 forbidden_public_keys, work) -> original bytes
```

Admission captures all independent scope before callbacks, authenticates the
actual root signature and canonical original, joins every scope field, parses
the actual Ed25519 proof key and checks its canonical PEM/SPKI. The result is
ordinary same-call data; no API accepts it in place of original signed bytes.
The producer owns its payload and key references, checks the actual root key
pair and separation, reserves its bounded signature output and genuinely
re-admits the exact signed result before returning it.

The proof key must differ from the root and every independently supplied role
key. `forbidden_public_keys` is an exact nonempty tuple with at most 16 actual
Ed25519 keys; repeated SPKIs are rejected even through distinct key objects.
Root is always checked separately and may also occur once in that tuple. The
consumer must supply genuinely admitted signer roles, including any required
intent or completion keys; the enrollment cannot discover unprovided keys and
makes no global separation claim about them.

The complete canonical envelope is limited to 16 KiB, 256 JSON nodes and depth
four. Age is positive and source-bounded; skew is nonnegative and source-bounded.
They are policy limits, not a newly issued clock interval. Both APIs retain the
supplied cumulative work and create no current-time allowance. The
[proof wire](oidc-session-activation-release-proof.md) remains distinct from this
root enrollment, and its actual producer/receiver must still bind genuine
committed originals, fresh release intent and independently authorized release
scope. No service, key provisioning, plaintext opening or public permission is
provided here.

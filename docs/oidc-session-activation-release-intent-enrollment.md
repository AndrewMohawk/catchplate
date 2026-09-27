# Private activation token-release caller enrollment

`oidc_session_activation_release_intent_enrollment.py` provides a distinct
root-signed enrollment for the signer of a private, fresh release intent. This
is source-only implementation: unbuilt, unexecuted and unprovisioned. Enrollment
alone does not authorize token disclosure or establish a committed consumption.

The fixed enrollment purpose is
`enroll-oidc-session-activation-token-release-caller`, separate from the intent's
`authorize-oidc-session-activation-token-release` purpose. The signed schema is
`serverware.signedOidcSessionActivationReleaseIntentEnrollment/v1`; its payload
and byte-identity domains are respectively
`serverware.oidcSessionActivationReleaseIntentEnrollment/v1` and
`serverware.oidcSessionActivationReleaseIntentEnrollmentIdentity/v1`.

The closed payload contains the current source revision, purpose, six scope
fields (`configurationDigest`, `databaseId`, `generationDigest`,
`runtimeClosureDigest`, `callerId`, `receiverIdentity`), `callerKey`,
`maximumAgeNs` and `maximumClockSkewNs`, plus its schema. Receiver identity is the
existing exact three-digest identity. The caller key has only canonical
`publicKeyPem`, `spkiDigest` and `measurementDigest`. Age and skew are positive-age
and nonnegative-skew policies bounded by the source verifier ceilings; they are
not an issued interval, renewed permission or a clock sample.

`_admit_on_work(enrollment_bytes=..., root_public_key=..., expected_scope=...,
forbidden_public_keys=..., work=...)` captures the exact six independently
provided scope fields before callbacks, verifies the actual root signature and
canonical bytes, checks every scope field, parses the caller's actual Ed25519
key and joins its canonical PEM/SPKI. It returns only same-call ordinary
`_Enrollment(payload, enrollment_digest, caller_public_key)` observations. No
API accepts that result in place of original signed bytes. `_scope(value, work)`
is a detached shape helper, not admission.

The caller key must differ from the root and every independently provided role
key. `forbidden_public_keys` is an exact nonempty tuple of at most 16 actual
Ed25519 keys; duplicate SPKIs inside it are rejected, including separate key
objects for the same key. Root is always checked separately and may also occur
once in the tuple. The release-custody integration supplies the actual original
planner and admitted current-root state, computation and completion keys. The
contract does not discover other configured keys and makes no global claim
about unprovided consume-grant or other signers. Consumers must supply the real
independently admitted roles, not keys learned from the enrollment under test.

`_produce_on_work(payload=..., root_private_key=..., root_public_key=...,
forbidden_public_keys=..., work=...)` owns the payload and all key references
before native callbacks, validates the root key pair and separation, reserves
the complete bounded signature output, signs only this fixed domain, and
genuinely re-admits its exact output before returning bytes. Both APIs use the
supplied cumulative work; neither creates a budget or clock window. The whole
canonical envelope is limited to 16 KiB, 256 JSON nodes and depth four.

The [release-intent wire contract](oidc-session-activation-release-intent.md)
and its actual producer/verifier remain separate from this root enrollment.
Release custody must independently pin the whole intent digest and authenticate
that original intent, old-token possession and its exact release scope. Packet,
commit, effects and completion/state-original admission, durable exact outcome,
guarded token opening and private handoff remain separate gates. The enrollment
measurement field is a signed identity claim, not measured execution evidence;
this module issues no keys, provisions no service and supplies no public
permission or production-verification claim.

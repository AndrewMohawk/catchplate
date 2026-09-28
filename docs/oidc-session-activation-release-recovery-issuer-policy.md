# Independent recovery grant issuer policy

`oidc_session_activation_release_recovery_issuer_policy` is a separate,
original-only root-signed policy for unchanged-outcome recovery. It does not
widen the existing live issuer policy or select a live grant by a recovery
flag. Its purpose is `issue-oidc-session-activation-release-recovery-grants`;
the signed and payload schemas are dedicated `...ReleaseRecoveryIssuerPolicy/v1`.

The closed payload has seventeen fields: schema, sourceRevision, purpose,
trustMode; proofEnrollmentDigest, intentEnrollmentDigest; proofScope, callerId,
expectedRelease, expectedEvidence, expectedOutcomeDigest; clientId,
clientIdentity, endpoint, releaseLaunch; issuedAtEpochNs, expiresAtEpochNs.
The actual existing proof scope7, release target6, evidence identities3,
client identity/endpoint and fixed release launch grammars remain authoritative.
The outcome digest and resource identities must be independently authorized,
never copied from an unverified candidate, grant response or directory scan.

`_verify_on_work` takes exact `policy_bytes`, `release_custody_bytes`,
`proof_enrollment_bytes`, `intent_enrollment_bytes`, the actual root public key,
original live window/deadline/work and optional restrictive `_continuity`.
`_produce_on_work` substitutes a payload for policy bytes and additionally takes
the actual root private key. It admits all supplied originals and the genuine
root key pair before signing, reserves canonical/signature output before
allocation, and authenticates the unchanged signed readback. Neither accepts a
successful material carrier or generates/delivers a key.

The custody pin uses the existing release-custody identity domain in
`expectedEvidence.releaseCustodyDigest`; enrollment identities use their
existing original domains. The verifier genuinely authenticates historical
custody and its original planner/state enrollment, joins configuration,
generation, runtime closure, receiver, delivery key/target and exact intent
identity, then separately admits both enrolled signers. The intent signer is
distinct from actual planner/state purposes and root; the proof signer is also
distinct from that intent signer. The proof scope and remaining expected
consume/evidence identities are independently signed policy pins, not proof
that execution or storage occurred.

Policy freshness is current. Old custody, intent and proof intervals are not
renewed, and no historical instant becomes the processing clock. The new
interval cannot exceed the original delivery expiry. The same opening samples,
work ceilings, nondecreasing clock floors and transport deadline persist;
enrolled ages/skew, planner policy and socket timeout can only tighten them.
Historical custody's optional `_current` hook forwards the original upstream
guard into its existing planner admission, with unchanged default behavior.
Child guards never call an aggregate that contains themselves.

The immutable same-call `_IssuerPolicyMaterial` retains the four originals,
policy digest/payload, actual historical custody material, independently admitted
public keys and base forbidden-key tuple, static client/endpoint/launch and
narrowed lifetime/guard. It is output data, not an authority input. Policy is
bounded to 64 KiB, 1,024 nodes and depth six; custody/enrollments retain their
existing bounds and the complete original inventory remains within 64 MiB.

This policy does not authenticate a request's proof/intent or old-token
possession, reconstruct an outcome, inspect a directory, create a checkpoint,
open ciphertext, authorize public WebAuthn or send a token. The separate
producer/receiver must genuinely admit their request originals and exact
outcome before producing/checking fresh recovery-profile grants. Checkpoint
one is an independently authorized requirement, not evidence that a record
exists; the actual recovery worker must read the exact already-retained record.
No service, provisioning, runtime evidence, retry or production closure is
established by this source slice.

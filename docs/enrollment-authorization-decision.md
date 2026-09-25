# Decision: dedicated control-plane enrollment authorization

Accepted by the user on 2026-09-25. Source checkpoint `.127`; implementation
only, unbuilt and unexecuted. Reasonable architecture choices within the agreed
scope will be made and recorded for later review. This does not authorize new
external access, production provisioning or bypassing release gates.

## Trust decision

The control plane owns current user/session authentication, role checks, CSRF,
bootstrap admission and the existing MFA/approval workflow. It issues a narrow
signed authorization for an independent registration evidence signer. The
signer verifies that authorization and the actual WebAuthn/source evidence; it
does not duplicate the control plane's login/session service.

This explicitly trusts the enrollment issuer's user admission. A compromised
issuer can authorize enrollment. A valid grant cannot replace the independent
signer's attestation, original-byte, source-proof or policy checks, but those
checks cannot establish that the issuer authenticated the intended user. If
that threat must be removed, the signer needs independently trusted identity
evidence, not another query to the same control-plane database.

The issuer key is dedicated to enrollment. It is not the HTTP response key, an
authority transport key, an evidence key or a transition-operation key.
The signed configuration independently pins its identity/key and the evidence
recipient. Possession of an arbitrary private key cannot enroll an issuer.
The policy validator checks separation from the keys present in the authority
configuration. The control plane's separate HTTP-response key is outside that
inventory; the new cold issuer owner compares its actual SPKI and rejects reuse
or later key/path drift. The policy mapper alone does not perform that check.

## Implemented source flow

```text
control-plane actor/session admission
    -> fixed configured issuer + original browser input commitments
    -> short-lived signed enrollment grant
                                    \
                                     -> configured grant/source verification
                                    /       -> durable one-attempt marker
signed verifier/planner source exchange      -> real attestation/evidence signing
```

`authority_webauthn_enrollment_issuer._produce_on_configuration` derives RP/origin,
issuer and recipient from the admitted configuration and signs through the
fixed grant producer. Its caller must already have performed the actual
control-plane authentication; a raw identity dictionary is not a proof of that.
Protected cold key delivery and the fixed private issuer owner are implemented
in [enrollment startup](control-plane-enrollment-startup.md). Public-route
orchestration and actual independent signer transport remain unfinished.

The closed `webauthnEnrollmentAuthorization` configuration extension is optional
but mandatory for this signing path. Absent/null grants no enrollment authority.
An enabled policy requires the explicit registration-evidence purpose, joins
the intended recipient key, verifies the issuer's real Ed25519/SPKI binding,
and rejects reuse of the other configured authority/evidence/transition keys.
The loader's planning inventory now agrees with the registered legacy/successor
union; legacy dispatch, execution, SQL and witness gates are not widened.

The new `signedPolicyAuthorityWebAuthnEnrollmentAuthorization/v1` has a dedicated
signature domain and a fresh random authorization ID. It binds source,
configuration/generation, issuer, recipient, user, label, challenge, optional
pending OIDC session, RP/origin, exact enrollment authorization, original
client-data/attestation digests and lengths, credential ID/transports, original
evaluation time and a bounded issuance/expiry interval. It contains no future
evidence signature or final execution request, avoiding a circular commitment.
Canonical original grant bytes, not a successful-verification object, enter
the signer. Its 64 KiB limit is a transport ceiling, not a promise that every
maximum-sized input fits cumulative work limits.

The actual exchange-signing continuation authenticates the grant, rejoins the
original browser inputs/time, verifies the signed source exchange and joins
challenge/session and configured RP/origin. User, label and enrollment
authorization are derived only from that grant. Source-control, grant and
evidence-envelope lifetimes remain distinct; none is renewed or silently
substituted for another. The grant does not grant business execution.

## One use means one attempt

`EnrollmentReplayStore` owns an explicitly provisioned private directory through
an independent descriptor, exclusive process lock and thread serialization.
It cold-recovers a bounded complete inventory of fixed immutable markers and
publishes/syncs a grant's marker before the evidence signature is attempted.
Every duplicate rejects, including a byte-identical retry. This is deliberately
one signing attempt, not a promise of one successfully delivered signature.

Invalid grant/source admission is rejected before consumption. After consumption,
a signing failure, expiry or lost result does not make the grant reusable.
Ambiguous journal I/O poisons that owner. No cleanup, TTL, automatic reset,
generation namespace or automatic retry is provided. The source ceiling is
4,096 records; exhaustion denies new attempts rather than erasing replay state.
Long-running archival/capacity management remains a separate unfinished
operational requirement, not implicit permission to clear this ledger.

All signer processes/replicas and restarts must preserve the same independently
admitted replay domain. A new directory is not a safe restart. Filesystem fsync
and local locks alone do not protect against a privileged host restoring an old
directory. Production needs protected durable storage and independent rollback
admission; this module does not claim to supply that infrastructure.

## Remaining integration

- Independently provision the dedicated issuer key, signed bootstrap and public
  policy for the implemented cold-start delivery. Enroll the optional key mount
  in the immutable deployment/readiness closure. No key or service is provisioned
  by this source change, and there is no generic response-key fallback.
- Connect the existing authenticated operator/OIDC finish handlers to the issuer,
  authenticated signer transport, custody and successor orchestration. Current
  public handlers still perform legacy finalization.
- Preserve complete sibling/history, prior publication and current-root/fence
  requirements. The grant and local replay marker do not replace those checks.
- Establish production replay storage/anti-rollback and capacity management,
  independent production services, immutable preparation and consolidated
  frozen-source verification.

No builds, imports, tests, SQL execution or runtime checks ran for this source.

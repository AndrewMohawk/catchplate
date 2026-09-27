# Activation execution-purpose authorization

This source-only seam authorizes an **already-produced exact activation plan**.
It is distinct from registration/finalization authorization and from permission
to decrypt an execution bundle. No public endpoint, actor permission, key
provisioning, reservation, SQL execution or token release is supplied here.

`authority_oidc_session_activation_execution_authorization.py` fixes operation
`oidc.session.activate` and purpose `authorize-oidc-session-activation-execution`.
Its caller enrollment and request have separate signature/identity domains.
An enrollment is at most 16 KiB; a request is at most 64 KiB. The actual
canonical decoder/signature checks use the caller's supplied cumulative work.

The independently root-signed enrollment binds configuration, database,
generation, original current-root/grant enrollment identities, caller identity
and key/measurement, grant-authorizer audience, planner SPKI, operation-root
SPKI and maximum age/skew. Original root/current-root/grant admissions and
actual key separation are mandatory. A planner sender or receiving-custody
bootstrap is not a substitute for this caller delegation.

The signed request additionally binds the genuine typed request and operation
IDs, exact signed-plan identity, purpose-framed raw2 identity, journal digest
and validated complete before-vector identity. Raw2 remains `(signed plan,
encrypted execution originals)`; plaintext tokens and keys are never added.
Subject identifiers are bound through the typed request, not an untrusted
successful-verification result. Request scope and caller ownership must be
independently admitted before invoking the signing producer.

## Explicit post-plan timeline

The activation planner generates the new token and typed request internally.
Therefore fresh execution authorization follows the plan; it does not reuse
finalization's authorization-before-new-plan rule. Both original signatures and
exact fingerprints are verified, and the signed intervals must satisfy:

```text
plan.issued <= authorization.issued < authorization.expires <= plan.expires
```

The producer samples its current issue time on the supplied original window.
It generates a nonzero 32-byte nonce with the actual `secrets.token_bytes`,
charged to that same work, and encodes the canonical 43-character unpadded
base64url `authorizationId`. There is no caller nonce or synthetic clock input.
The producer re-verifies the signed output before return. Neither a nonce nor
the signature grants one-use execution: that remains reservation/SQL work.

All processing retains the supplied opening samples and inherited monotonic
deadline. Enrollment limits, authorization expiry and original plan expiry may
only narrow that bracket. No new window, work allowance or historical expiry
bypass is created. Existing registration/finalization timelines are unchanged.

## Fixed receiving composition

The authorization module exports `_admit_enrollment_on_work`,
`_produce_enrollment_on_work`, `_produce_on_work` and `_verify_on_work`.
Enrollment APIs use `operation_public_key`, independently joined to the actual
root key, plus the dedicated planner key. Live request APIs take the exact
raw2, independent `{request, scope, journalDigest}` expectations, before-vector,
all three enrollment originals and the original window/deadline/work.
The request producer additionally requires the independently held caller private
key. It requires prior present-purpose admission; it does not establish it.

`authority_oidc_session_activation_execution_grant_production._produce_on_work`
takes these original inputs, original signed authorization, an independently
held grant signer and the exact `OidcSessionActivationExecutionCustody` owner
for consumer role `grant`. It authenticates caller authority before invoking
the actual generic grant producer. Private same-call observations do not form
an external proof input.

Before the grant signature, genuine private original replay supplies the typed
request/operation, plan/raw2/before-vector identities and complete effects.
Those facts must match the independently authenticated caller authorization.
The grant keeps its **original plan issue time**, as required by the existing
grant format; it does not claim that post-plan authorization existed then.
Its expiry is clipped to the original plan, caller, grant-policy and processing
bounds, and actual caller liveness is checked through signing and return.
Only the original signed grant bytes return.

The **grant** receiving role now has source-connected independent
[launch admission](oidc-session-activation-execution-authorizer-bootstrap.md),
sealed [key/FD delivery](oidc-session-activation-execution-authorizer-delivery.md)
and an actual service invoking this genuine authorization/grant composition.
Its units are packaged source inputs, not a built, installed or executed service.
The dedicated [reserve receiver](oidc-session-activation-execution-reserver-delivery.md)
now connects genuine caller/grant replay and durable exact reserve/ACK storage.
Dedicated **SQL** receiving delivery/service composition and its independently
current pending admission remain open.
The public caller still needs a separate purpose/key lifecycle and fresh actor
permission; old registration/control-plane evidence keys cannot silently gain
this purpose. No AES keys are given to a signing-only caller. Genuine
pending-state consumption, one-use protected SQL, completion/history, public recovery and
protected token release remain separate. This is not a complete activation or
session-currentness result. No tests, imports, builds or runtime verification
were run.

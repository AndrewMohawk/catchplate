# Registration evidence execution authorization

This source slice adds a separate, root-delegated caller permission for the
fixed `webauthn.registration.evidence.admit` successor operation. It is a
prerequisite for producing an execution grant, not a cold authorizer service,
public registration route, reservation or database operation. The current tree
is unbuilt and unexecuted.

## Evidence signing is not execution permission

The existing [control-plane enrollment grant](enrollment-authorization-decision.md)
has purpose `authorize-webauthn-registration`. It permits the configured signer
to evaluate original registration inputs and attempt an evidence signature.
Its operation string does not grant SQL permission. Neither that grant, the
resulting evidence signature nor a planner signature can be relabelled as
caller authorization to execute a successor.

The new purpose is `authorize-registration-evidence-execution`, with its own
signed enrollment, request signature domain and dedicated caller key. It
authorizes only the exact registration **evidence-admission** request. It does
not authorize a separate credential-finalization operation or confer generic
registration, revocation or transition privileges.

## Root-delegated caller and fixed scope

[`authority_registration_execution_authorization`](../serverware/authority_registration_execution_authorization.py)
admits and produces the dedicated authorization enrollment. Genuine original
current-root and successor-grant enrollments supply the database, generation,
enrollment identities and intended grant-authorizer audience. The independent
root delegates the fixed purpose to a caller identity, actual Ed25519 public
key/SPKI and measurement, with an independently supplied configuration digest
and bounded age/skew policy. Those pins are not inferred from the request being
authorized.

The actual caller key must be separate from the root, current-root computation,
completion and state keys, the successor grant authorizer, and the actual
planner and registration-evidence keys. The existing enrollment-signing key is
not an automatic fallback. Root signing authenticates the delegation; it does
not establish measurement provenance, private-key protection or an actual
user/session admission.

The enrollment envelope is
`serverware.signedPolicyAuthorityRegistrationExecutionAuthorizationEnrollment/v1`.
Its closed payload has 14 fields; original enrollment bytes are bounded to
16 KiB. The request envelope is
`serverware.signedPolicyAuthorityRegistrationExecutionAuthorization/v1`, with
exactly `schema`, `payload` and `signatureBase64Url`. Its closed 18-field payload
binds the same scope, authorization-enrollment identity, typed request digest,
operation identity, fresh nonzero 32-byte authorization ID and original issue/
expiry interval. Its original-byte cap is 64 KiB. Neither envelope carries an
arbitrary operation list or a caller-selected successful execution result.

## Actual originals through plan and grant production

The private
[`authority_registration_execution_issuance._produce_on_configuration`](../serverware/authority_registration_execution_issuance.py)
composition starts with original raw8 registration source-exchange frames and
raw2 signed evidence output. It reconstructs the actual typed evidence request
through the genuine original-input path before signing caller authorization.
A supplied request dictionary, plan digest or successful-verification object
cannot replace those originals.

The actual authenticated caller owner must separately admit this new execution
purpose and the caller's present permission before invoking the producer.
Possession of the old enrollment grant or evidence originals does not supply
that permission. The return value is original signed authorization bytes, not
an accepted request object or a successful-execution result.

The private
[`authority_registration_execution_grant_production._produce_on_work`](../serverware/authority_registration_execution_grant_production.py)
authenticates the original authorization, then genuinely replays the original
raw3 plan. It joins the resulting typed request digest and operation identity
to that authorization **before successor-grant signing**. It does not change
plan production or accept an incoming successful replay object. The framed
authorization-original identity supplies
`requestAuthorizationDigest`; copying a digest from a plan or request does not
establish that permission.

All admission and production retain the existing cumulative work and original
live windows. The plan's original issue time cannot precede the authorization's
issue time. Authorization expiry cannot renew old evidence or plan validity,
and later grant/reserve expiry cannot extend the authorization. The authorization
ID separates requests but is not a durable replay ledger or a one-use guarantee.
The original bytes remain required at each authentication boundary; an internal
parsed result is not a transferable permission token.

## Remaining cold and production boundaries

This batch creates no process owner, inherited-FD inventory, listener, HTTP
route, private-key mount, service unit or installer setting. A future cold owner
must independently admit the purpose-only key, root/configuration/enrollment
originals and original lifetime without sharing general response, planner or
evidence keys. Existing cold enrollment and registration-signer owners are not
silently extended to hold this new authority.

No reserve, current-root pending decision, custody packet, attempt marker or SQL
write follows from issuing or verifying this authorization. The separate
[successor execution path](authority-successor-execution.md) still requires
genuine grant/plan admission, complete roots and history, independently current
checkpoints, protected custody, durable one-attempt handling and actual
transaction ownership. Public finalization remains separate.

Independent caller admission, protected key/service provisioning, rollback
protection, immutable preparation and consolidated frozen-source verification
remain outstanding. A root-delegated assertion is not proof that a deployed
process performed those steps.

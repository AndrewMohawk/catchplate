# Registration evidence execution authorization

This source slice adds a separate, root-delegated caller permission for the
fixed `webauthn.registration.evidence.admit` successor operation. It is a
prerequisite for producing an execution grant, not a reservation or database
operation. Separate source now supplies a
[cold authorizer](registration-execution-authorizer.md) and an opt-in
[control-plane caller path with explicit public preparation gates](control-plane-registration-execution.md#public-preparation-endpoints).
The current tree is unbuilt and unexecuted.

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

[`authority_registration_execution_authorization`](../catchplate/authority_registration_execution_authorization.py)
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
`catchplate.signedPolicyAuthorityRegistrationExecutionAuthorizationEnrollment/v1`.
Its closed payload has 14 fields; original enrollment bytes are bounded to
16 KiB. The request envelope is
`catchplate.signedPolicyAuthorityRegistrationExecutionAuthorization/v1`, with
exactly `schema`, `payload` and `signatureBase64Url`. Its closed 18-field payload
binds the same scope, authorization-enrollment identity, typed request digest,
operation identity, fresh nonzero 32-byte authorization ID and original issue/
expiry interval. Its original-byte cap is 64 KiB. Neither envelope carries an
arbitrary operation list or a caller-selected successful execution result.

## Actual originals through plan and grant production

The private
[`authority_registration_execution_issuance._produce_on_configuration`](../catchplate/authority_registration_execution_issuance.py)
composition starts with original raw8 registration source-exchange frames and
raw2 signed evidence output. It reconstructs the actual typed evidence request
through the genuine original-input path before signing caller authorization.
A supplied request dictionary, plan digest or successful-verification object
cannot replace those originals.

The actual authenticated application must separately admit this new execution
purpose and the caller's present permission before invoking the producer. The
new [prepare-execution handlers](control-plane-registration-execution.md#public-preparation-endpoints)
perform that admission using current operator/session authority, fresh
first-credential bootstrap permission or the new mutation assertion and
configured two-person approval. Those branches cannot substitute for each other:
no-history preparation rejects MFA and requires a fresh configured bootstrap
token even in development; any-history preparation rejects that token and binds
the assertion/approval to the actual registration challenge and request digest.
The deterministic binding commits the actual
registration originals and new purpose; an evidence-only MFA wrapper is not
the required assertion. Private direct callers retain the same obligation.
Possession of the old enrollment grant or evidence originals does not supply
that permission. The return value is original signed authorization bytes, not
an accepted request object or a successful-execution result.

The private
[`authority_registration_execution_grant_production._produce_on_work`](../catchplate/authority_registration_execution_grant_production.py)
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

The separate [cold execution-grant authorizer](registration-execution-authorizer.md)
now has source for its own process owner, fixed four-FD delivery, private
original-input transport and uninstalled packaging. It owns the dedicated
grant-authorizer key, not the caller-authorization key. Existing cold enrollment
and registration-evidence signer owners are not silently extended or given
SQL authority. The opt-in control-plane enrollment bootstrap v3 now retains the
separate caller key and three original enrollments, with private methods for
authorization, one authorizer exchange and genuine local grant verification.
V2 remains evidence-only. Separate source now adds two explicit public
preparation handlers with actual present-caller/new-purpose gates; the old
`/prepare` and `/verify` routes are unchanged. This API-only preparation neither
executes the grant nor completes the operator UI workflow. The private preparation returns raw10
in memory; the separate [prepare-and-retain composition](control-plane-registration-execution.md#explicit-local-retention)
now durably stores those originals and returns only a local content ID.
This retention-only record is not a one-use reservation or renewed authority.

No reserve, current-root pending decision, custody packet, attempt marker or SQL
write follows from issuing or verifying this authorization. The separate
[successor execution path](authority-successor-execution.md) still requires
genuine grant/plan admission, complete roots and history, independently current
checkpoints, protected custody, durable one-attempt handling and actual
transaction ownership. Public finalization remains separate.

Later execution-action admission, protected key/service provisioning, rollback
protection, immutable preparation and consolidated frozen-source verification
remain outstanding. A root-delegated assertion is not proof that a deployed
process performed those steps.

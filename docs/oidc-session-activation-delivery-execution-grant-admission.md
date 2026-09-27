# Consume-grant original admission

The private [shared admission module](../serverware/authority_oidc_session_activation_delivery_execution_grant_admission.py)
connects the actual consume-only caller authorization, dedicated root delegation
and independent receiving custodian to the grant producer and verifier. It is
not a public permission endpoint, signing service or accepted proof-result format.

## Inputs and boundaries

Both consumers supply original caller authorization and enrollment bytes,
current-root and grant enrollment originals, the exact signed-plan/ciphertext
pair, independently expected request/scope/journal identity and complete before
vector, independently selected public keys/configuration, the actual receiving
owner, and the existing work/window/deadline. The verifier additionally holds
its original grant before any capture or cryptographic callback.

All immutable originals and owner configuration are held before graph capture.
The aggregate 64 MiB bound includes the receiving owner's four detached custody
originals and the optional grant, not just the ciphertext. The same work budget
pays for capture, signatures, hashes, proof replay and final checks. No success
object, unsigned scope from the stored ciphertext, caller-selected clock or
replacement budget can substitute for these inputs.

Caller admission authenticates the exact signed plan and all enrollments.
The grant key is separate from the root, state and planner purposes; root and
current-enrollment originals also join the actual receiving owner. The verifier
checks the enrolled grant signature and static caller/original commitments
before private ciphertext opening. Receiving bootstrap/history reauthentication
and genuine full original-proof replay occur through the actual receiver once
per issuance or verification invocation, under its independently pinned scope.

The complete request, original plan/ciphertext bytes, retained record and before
vector must agree with caller control. After-roots and result digest come from
that replay. Raw-frame descriptors are SHA-256 commitments to the exact original
bytes. The token-free result uses the existing controlled-writer result digest
domain; no generic grant or replay operation registry gains consume authority.

## Time and lifecycle

The grant preserves the plan's original issue instant as its interval anchor;
it does not claim that the signing operation happened at that instant. Actual
post-plan caller authorization retains its own signed issue time. Grant expiry
is no later than original plan expiry, caller expiry, genuine replay validity,
the inherited narrowed window or original issue plus enrolled maximum age.

Actual epoch/monotonic guards bracket admission, replay, signing and returned
verification. They retain the original opening, stricter transport deadlines,
clock-skew limits and actual receiving-owner lifecycle. The returned guard
cannot renew the plan, revive historical execution or establish off-host
currentness. Private same-call projections are not accepted service inputs.

## Integration and remaining work

The [producer](oidc-session-activation-delivery-execution-grant-production.md)
signs only these derived claims. The [independent verifier](oidc-session-activation-delivery-execution-grant-verification.md)
reauthenticates originals and compares the same claims. The [wire contract](oidc-session-activation-delivery-execution-grant.md)
alone provides neither role admission nor original replay.

Cold signing-key/descriptor admission and an isolated grant service remain A12.
Reservations, one-use SQL, completion/recovery, plaintext release and fresh
public/user permission remain separate unfinished scopes. These are source-only
implementations: no build, import, test, runtime, deployment or production
acceptance is asserted.

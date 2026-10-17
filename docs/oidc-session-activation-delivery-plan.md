# Signed activation-delivery consumption plans

Source implementation only: unbuilt and unexecuted. This is the private plan
for `oidc.session.activation-delivery.consume`, not an execution grant, SQL
commit, durable retained record or plaintext-token release.

[`authority_oidc_session_activation_delivery_plan.py`](../catchplate/authority_oidc_session_activation_delivery_plan.py)
provides `_produce_on_work`, `_verify_full_on_work` and `_verify_on_work`.
The producer returns only canonical signed envelope bytes. The full receiver
returns this call's genuine replay facts and current guard; the smaller
receiver returns its actual `KernelTransition`. No API accepts either result
as proof. All entrypoints require the original work allowance, live window
and positive inherited transport deadline.

## Original inputs and independent scope

Each call supplies the typed consume request, original old-token bytes,
database time, selected rows, complete query records, primary/range proofs,
independent business/authorization roots, seven counted heads and the original
five-index write proof. The exact fourteen-field scope binds the six subject
IDs, authentication/trust policies, configuration, planner identity/SPKI,
maximum plan age/skew and deadline. The planner public key is independently
held; production also requires its genuine private-key pair.

The state enrollment, root public key, complete root vector, nonce-bound
consume query and signed head observation are original inputs, not claimed
digests. The distinct state verifier authenticates them, rejects pending state
and joins the full-vector projection to the independent roots and seven heads.
This observation is not an atomic SQL lock or off-host currentness witness.

Completed-activation provenance uses one immutable `activation_originals`
tuple of exactly thirteen frames, in this order:

| Index | Original |
| --- | --- |
| 0–3 | Completion status, completion-request identity, signed completion, state ACK |
| 4–5 | Signed activation plan and encrypted activation-original bundle |
| 6–8 | Signed reservation request, reservation receipt, computation snapshot |
| 9–10 | Caller authorization and execution grant |
| 11–12 | Caller enrollment and grant enrollment |

`_activation_originals(values, work)` applies the actual per-frame and aggregate
bounds before callbacks. Transport shape alone authenticates nothing.
Independent `activation_expectations` retain the original request, scope and
journal digest. The separate closed `activation_scope` contains
`authorizationDigest`, `databaseId`, `generationDigest`, `pendingSequence`,
`pendingHeadDigest` and `fence`. Original state enrollment/root/configuration,
activation planner and operation keys, and the actual historical custody owner
remain independently supplied; they are not learned from returned ACKs.

## Genuine replay and signed commitments

Both production and receiving call the actual
[completed-activation provenance verifier](oidc-session-activation-delivery-provenance.md)
and [indexed consumption replay](oidc-session-activation-delivery-writes.md).
The former authenticates the historical activation/completion chain and joins
the exact original delivery INSERT to the supplied current row. The latter
separately proves current membership, old-token possession, current policy and
the three real effects: delivery update, audit insertion and audit-capacity
update. A historical ACK cannot replace those current proofs.

The distinct [plan contract](../catchplate/authority_oidc_session_activation_delivery_plan_contract.py)
has a closed 22-field payload and a 16 KiB envelope cap. Separate domains commit
the original read/write proof, independent context, private-original digest/count
projection, and the genuine indexed transition including effects, after-roots
and all seven after-heads. Tokens and keys are never serialized into the signed
envelope; the private input commitment contains only derived digests/counts.
The aggregate original/body ceiling remains 64 MiB, with the cumulative supplied
work allowance still limiting actual copying, hashing and crypto.

All mutable graphs are detached before hash/clock/native callbacks. The actual
historical owner binds the independent root/enrollment and may only narrow the
current processing bracket. Its fresh outer custody does not renew the old
activation interval. Current state expiry, delivery replay lifetime, scope
policy, original window and inherited deadline bound signing. Actual provenance
and write-replay guards remain checked through signature creation/verification
and return. Receiving first authenticates the known consume-plan signer, then
repeats all original replay and commitment comparisons.

There is no expired consume-plan adaptation, cross-configuration history
resolution, generic execution-factory bypass, durable first-exact publication,
SQL retry, committed-consumption release admission or public handoff here.
See the [read acquisition](oidc-session-activation-delivery-planning.md) and
[consumption transition](oidc-session-activation-delivery-consumption.md) for the
adjacent source boundaries. Cold purpose delivery, retention and the remaining
protected issuance/SQL/recovery/release integration are separate work.

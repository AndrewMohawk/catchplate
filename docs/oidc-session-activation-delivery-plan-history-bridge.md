# Historical activation evidence in a fresh consume plan

The protected delivery planner can now use independently authenticated old
activation evidence while evaluating a fresh consume action against current
state. This is a preparation/export source connection, not consume execution,
SQL completion, token release or permission to retry an uncertain operation.
The public historical consume execution gate remains closed.

## Actual authority split

`authority_oidc_session_activation_delivery_plan.py` keeps its existing original-only
production and receiving signatures. Current state enrollment, complete vector,
head query/observation, consume scope and write replay stay under the independently
configured current root. The supplied activation planner and operation keys keep
their old-evidence meaning; neither is a new current-state authority parameter.

Only the actual request-bound v7 history custody owner selects the bridge path.
Its class-selected `_consume_context_on_work` re-admits its own immutable custody
and signed issuer policy under the current outer root, joins the exact current
configuration and state enrollment, and returns same-call old root, state,
configuration, planner and operation-key facts. The lower planner checks the
supplied old keys against those facts and uses them only for genuine completed
activation provenance replay. No incoming material object or version flag can
replace original admission.

The signed bridge requires complete equality of the independently authenticated
old/current state-enrollment payloads: database, generation, initial vector, role
keys, measurements and limits. Signature envelopes may differ, allowing explicit
root re-signing. This is not arbitrary generation, database or state migration.
Original delivery expiry, old possession, current trust and current write proofs
remain real checks; historical evidence does not renew the delivery lifetime.

## Versioned private commitment

Legacy plans keep `DeliveryPrivateInputs/v1` exactly. An actually admitted bridge
selects `DeliveryPrivateInputs/v2` for both the private body and its signed opaque
input commitment. In addition to the existing old token, current-state originals
and activation raw13 inventory, v2 commits the exact old state enrollment and
exact current-root-signed bridge policy as digest/byte-count pairs. Every input
field uses the selected version's framing domain.

The purpose-specific custody envelope is held and re-admitted but is not part of
this cross-role commitment. A future independently authorized receiving role
must authenticate its own custody and the same policy/state originals; it cannot
substitute the planning role. The outer plan envelope and other body domains stay
unchanged because the signed input digest commits the exact versioned body.
Production and genuine live receiving recompute this same body; no raw hint
selects its version.

## Capacity and continuation

Before the bridge custody is decoded again, the planner accounts for four
representations of its actual held originals, detached caller graphs and query
originals/metadata, plus 64 KiB. The custody helper adds its existing fixed
reservation of eight custody-original representations, four current-enrollment
representations and 64 KiB. Oversized combinations fail within the unchanged
64 MiB ceiling; these are conservative encoded/graph reservations, not a claim
about total Python heap usage or a new work allowance.

The actual context retains a base-only, lock-free custody guard. Descendant
provenance and write checks receive only this ancestry plus the original clock
guard, never a child guard fed back into its ancestor. Original window origin,
deadline, age and skew can only narrow. Legacy roles and `historical=True`
completion retain their strict existing root/state binding and v1 commitment.

## Remaining execution boundary

The grant, reserve, SQL and completion custody profiles do not yet carry and
authenticate this bridge. Their separate purposes cannot be replaced by v7
planning custody. They need explicit role-specific original admission and matching
receivers before the public historical consume action can be enabled. Historical
planner-v3 completion additionally needs original bridge/plan interval replay
under fresh completion-purpose processing authority, rather than reusing a live
issuer-policy admission to renew or reject the original interval.

This slice was authored and source-read only: no build, test, interpreter, runtime,
browser, AWS or provisioning validation was performed.

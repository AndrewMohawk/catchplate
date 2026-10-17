# OIDC activation indexed write replay

[`authority_oidc_session_activation_writes`](../catchplate/authority_oidc_session_activation_writes.py)
encodes fixed write-proof originals and genuinely replays the activation
transition plus primary/counted-index mutations. This is source-only proof
composition, not SQL execution, a committed session, token delivery, index
population admission or an independent currentness witness.

## Original codec

`_encode_on_work(*, request_digest, counted_before_heads, write_inputs, work)`
accepts 13 actual `CompleteReadWriteHead` records and 12 actual
`IndexedMutationInput` records. `_decode_on_work(raw, *, work)` returns ordinary
`request_digest`, `counted_before_heads` and `write_inputs` fields. Neither
function authenticates a signature or grants semantic authority; a composing
signer/receiver must run the original replay.

The closed canonical `catchplate.oidcSessionActivationWriteProof/v1` object
contains `schema`, `sourceRevision`, `operation`, `requestDigest`, `beforeHeads`
and `writeFrontiers`. Each sorted head contains only `indexId`, `indexRevision`,
`rootDigest` and `leafCount`; each frontier contains its fixed index ID and the
actual leaf/opaque records. Unknown fields, profiles, duplicate/reordered heads,
noncanonical bytes and unsupported source revisions fail closed. The framed
identity domain is `catchplate.oidcSessionActivationWriteProofIdentity/v1`.

The inventory is the complete source-derived union: two session indexes, five
delivery indexes, three credential indexes, two challenge indexes and the
read-only pending-publication index. All 12 affected write profiles are required,
including profiles where both old and new rows are nonmembers. The publication
head is retained unchanged. Per-profile frontier limits come from the actual
six-mutation source contract; the outer original ceiling is 64 MiB, one million
JSON nodes and depth eight. Repeated capture/parse/encoding/proof work consumes
the same cumulative allowance, so these outer limits are not a promise that a
maximum-sized original fits the remaining invocation budget.

## Genuine replay and commitments

`_replay_on_work` takes the [full transition's original inputs](oidc-session-activation-transition.md),
the immutable `write_proof_bytes`, and independent `expected_counted_heads`:
an exact sorted tuple of 13 closed four-field dictionaries. Every decoded head
must equal that independent inventory, and the seven original read heads must
join it exactly. Signed proof contents cannot supply their own accepted roots,
revisions or expected head scope.

The function detaches policy, row, root, read-proof and head graphs before
native proof work. It invokes the real full transition on the original
assertion/tokens/envelope/key and policies, including genuine primary/range
admission and the shared audit-capacity finalizer. It does not accept a
successful transition, mutation set or acquisition result as proof. The real
`evaluate_indexed_primary_batch` then folds the actual six mutations and all 12
original write frontiers. Its limits are clipped to the existing work's remaining
allowance, and genuine measured costs are charged back to that same allowance.
Failure does not create a replacement allowance or retry.

The private ordinary result has `transition`, `write_proof_bytes`,
`write_proof_digest`, `transition_bytes`, `transition_digest`,
`business_after_roots`, `authorization_after_roots`, `counted_after_heads`,
`live` and `valid_until_epoch_ns`. No external entrypoint accepts this result
as authority. The transition commitment uses the distinct
`catchplate.oidcSessionActivationIndexedTransition/v1` schema and
`catchplate.oidcSessionActivationIndexedTransitionIdentity/v1` framed domain.
It binds source, operation, request and write-proof identity; all six mutations;
the actual result and already-complete `workUnits`; and genuine calculated
business/authorization after roots plus all 13 after heads. Query/framework
units and audit capacity must not be counted or finalized again.

The original `live` closure and validity bound are preserved through proof
evaluation, commitment construction and return. A composing signer must still
check that same closure/bound after its own work; no processing clock, assertion
expiry or delivery expiry is renewed. Plaintext tokens and the custody key are
not encoded in either commitment. The actual encrypted delivery remains in its
derived mutation.

The [signed planner](oidc-session-activation-plan.md) now consumes this genuine
replay, and [cold configuration](oidc-session-activation-planner-delivery.md)
supplies authenticated launch policy/key/snapshot pins. Independent currentness,
present subject permission, protected one-use SQL and committed token delivery
remain separate obligations. Planned frozen verification includes omitted/extra
profiles, tampered frontiers/primary proofs, independent-head mismatches,
unchanged read-only heads, exact after-root/effect commitments, expiry during
folding/signing and shared-work exhaustion. No build, test or runtime validation
has run for this source.

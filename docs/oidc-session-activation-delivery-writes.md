# Protected delivery-consumption indexed effects

This `.157` adapter is **source-only, unbuilt and unexecuted**. It derives
protected write commitments; it is not the SQL executor, a committed-consumption
receipt, a browser token response or the complete token-release milestone.

[`authority_oidc_session_activation_delivery_writes.py`](../serverware/authority_oidc_session_activation_delivery_writes.py)
handles only `oidc.session.activation-delivery.consume`. Its closed original
format is `serverware.oidcSessionActivationDeliveryWriteProof/v1`, with the exact
current source revision, operation, request digest, seven counted before-heads
and five write frontiers. Canonical encoding is ordinary bounded data, not proof
that any transition or database mutation happened.

## Genuine same-call semantics

The private `_replay_on_work` entrypoint accepts an actual `KernelContext`,
original pending-token bytes, independently pinned delivery/session/user/
credential/challenge identities and policies, original primary/range proofs,
independently admitted roots and counted heads, and the original write-proof
bytes. It accepts no precomputed transition, successful verifier object or
callback that could replace the actual semantic worker.

All mutable input graphs are detached before decoding, hashing or native clock
callbacks. The existing work allowance, clock opening and absolute transport
deadline are mandatory and cannot be renewed. The actual
[consumption transition](oidc-session-activation-delivery-consumption.md)
reverifies the current reads and original pending-token possession, then derives
the delivery update, deterministic audit insertion and actual audit-capacity
update. Its returned result is token-free and does not assert committed execution.
The indexed adapter does not add the capacity effect a second time.

## Complete counted-write closure

| Counted profile | Treatment |
| --- | --- |
| Delivery session, old token, new token, assertion and challenge indexes | Five genuine write frontiers; the changed primary row digest must be reflected in every index |
| Session token index | Read-only singleton proof; head retained unchanged |
| Pending trust publication index | Read-only empty-range proof; head retained unchanged |

Marking `consumed_at` does not remove the delivery from those five indexes.
Unchanged index keys are not permission to omit their changed primary-row
commitments. The adapter checks the fixed sorted inventory, joins every read
head and embedded write head to independent expectations, and requires the
actual mutation tables' complete profile set to match all five frontiers.

The real `evaluate_indexed_primary_batch` computes primary and counted after
roots from the same captured selected rows, original proofs and actual derived
mutations. Its limits are clipped to the caller's remaining cumulative budget;
its metrics are charged back to that budget. Live checks also retain the actual
semantic expiry throughout indexed work and commitment serialization.

The ordinary result contains exact proof/transition bytes and their distinct
domain-separated digests, primary after roots, all seven counted after-heads,
and this call's live guard. These outputs can feed a future genuinely authenticated
planning composition, but cannot be accepted as an input proof elsewhere.

## Remaining release boundary

Independent current roots, complete index populations, database time, caller
authority and original activation-completion provenance remain composing-owner
obligations. This source does not register a generic kernel, authorize a SQL
role, sign a plan/grant, execute consumption or return plaintext.

The design uses the existing immutable protected execution packet and commit
marker to retain the exact consumed effect and encrypted delivery for authorized
recovery. That integration is still open: an unsigned observation, `consumed_at`,
an activation ACK or this private derived result cannot establish that the new
consumption operation committed. Actual original commit admission and a distinct
one-use release/cold handoff must precede plaintext delivery. No legacy
environment-key decryption or direct-UPDATE fallback is introduced.

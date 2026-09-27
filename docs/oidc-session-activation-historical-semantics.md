# Historical OIDC activation semantics

This source-only historical replay separates original validity from current
processing liveness. It does not execute activation, release a token, authorize
a caller, renew an expired plan or permit a retry. It is unbuilt and unexecuted.

## Original replay contract

`authority_transition_oidc_session_activation._full_transition_historical_on_work`
has the existing full-transition original inputs plus the required immutable
`historical_plan_interval=(issued, expires)`. The caller must genuinely
authenticate that original signed plan interval, independently admit its policy
and roots, and supply the original UTC database cutoff. The interval is ordinary
data, not a verified capability. No entrypoint accepts an earlier successful
assertion, delivery or transition result in place of original bytes and proofs.

The method returns the distinct frozen `_HistoricalFullTransition` with
`transition`, `live`, `valid_until_epoch_ns` and `historical_plan_interval`.
`live()` checks the real current processing window, sticky epoch/monotonic
samples and inherited absolute deadline. `valid_until_epoch_ns` is the original
row/challenge/delivery lifetime ceiling; it may be in the past. Comparing current
time to that old ceiling would incorrectly turn history into a live admission.
Instead, the authenticated original plan expiry must fit the ceiling
algebraically. No new work budget or window is opened.

The historical path:

- Replays the actual primary and complete-query originals against independently
  supplied roots, selected rows and read heads. The original database cutoff
  must precede plan expiry; the plan verifier separately retains the original
  policy skew for its lower bound against signed issue time.
- Calls `_derive_historical_on_work` with original assertion/token bytes,
  historical rows, the authenticated interval and original database cutoff.
  It repeats the target/RP/origin/challenge/counter checks and actual assertion
  signature verification. Session and challenge expiries must contain the
  original plan expiry; row creation, update, attestation and last-use times
  cannot follow the original cutoff. Its distinct historical CAS-intent schema
  is ordinary derived data, not activation permission.
- Revalidates the selected RBAC and trust publication/high-water relationships
  and policy eligibility at that original cutoff. These historical inputs do
  not establish today's RBAC, trust, latest head or caller permission.
- Derives the original request-bound delivery ID, scope and TTL from the same
  selected rows and database cutoff. `_delivery_row_historical_on_work` genuinely
  authenticates AES-GCM, all eleven associated-data fields and the decrypted
  token digest with the independently supplied custody key. The original
  delivery lifetime remains bounded to at most 60 seconds and must contain the
  original plan expiry. Only ciphertext-bearing row data is returned; no
  historical plaintext-return, resealing or token-generation API is added.
- Reconstructs the same five business effects and invokes the real audit-capacity
  finalizer, yielding the same six-mutation transition and source work total.
  Original absent delivery/audit rows, counter behavior and effect timestamps
  are checked again, not inferred from stored success flags.

Historical issue and database cutoff cannot be in the future beyond the current
processing skew. Their past values are never substituted for a processing clock
or passed as a fake `now` to a live verifier. Shared code handles original-byte
semantics; dedicated historical entrypoints select separate algebraic lifetime
rules. Existing live APIs retain their signatures and expiry checks.

## Remaining boundary

This is the semantic prerequisite for genuine expired-original recovery, not a
cold historical custody service or signed completion acknowledgment. Existing
generic completion paths continue to reject activation until a separately
admitted historical custody path is implemented. Protected committed-token delivery,
present-caller public permission, explicit recovery and portal/current-auth
confirmation remain separate work. No infrastructure, keys or filesystem paths
are provisioned, and no runtime or production-verification gate is closed here.

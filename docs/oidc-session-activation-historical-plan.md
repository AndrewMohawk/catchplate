# Historical activation indexed writes and signed plan

This source-only prerequisite reconstructs an authenticated original activation
plan after its execution interval has expired. It does not renew that interval,
execute SQL, sign completion, release a token or authorize recovery. Generic
activation completion remains closed until a separately admitted historical
cold custody path exists. No build, test or runtime execution was performed.

## Distinct original-only APIs

[authority_oidc_session_activation_plan.py](../serverware/authority_oidc_session_activation_plan.py)
adds `_verify_historical_full_on_work` with the same explicit original keyword
inputs as `_verify_full_on_work`. It requires the real signed envelope,
independent typed request/scope and keys, original assertion/tokens/delivery
envelope, original primary/range/write proofs, independent roots/head union and
state originals, plus current work/window and a positive inherited deadline.
No previously successful plan or transition object is accepted.

The historical verifier returns distinct `_HistoricalVerifiedPlan` fields
`invocation`, `write_result`, `payload` and `plan_digest`. Its invocation is
distinct from the live family. `_historical_live(invocation, work)` returns the
same call's retained current-processing guard and requires the same work object.
Live `_capture`, `_produce_on_work`, `_verify_full_on_work`, `_verify_on_work`
and their signatures retain active-expiry checks; they do not route to history.

[authority_oidc_session_activation_writes.py](../serverware/authority_oidc_session_activation_writes.py)
adds `_replay_historical_on_work`: the existing original write-replay inputs plus
`historical_plan_interval`, the exact authenticated `(issued, expires)` pair.
Only the plan verifier supplies that pair after verifying the original signature.
Its distinct `_HistoricalReplayedWrites` exposes the same original commitments,
true transition, after-roots and thirteen after-heads, plus the original interval.
The live write entrypoint remains unchanged and rejects expired originals.

## Authenticate, then rederive

All mutable request/policy/row/root/proof/head graphs and immutable original
bytes/keys are held before cryptographic or clock callbacks. Actual typed
request and operation identities are recomputed. The original plan signature
must match independently supplied configuration, planner identity/SPKI and
request pins before its interval reaches any historical semantic verifier.

The actual historical state verifier rechecks original root enrollment and
signed nonce/context/vector-bound no-pending observation. Its genuine complete
vector projection must equal the independently captured primary roots and all
thirteen counted heads; neither stored descriptors nor signed write-proof heads
become independent expectations by themselves.

The actual historical transition replays the original assertion, selected-row
identity/RBAC/trust joins, original encrypted delivery and full primary/range
proofs. It derives the five business effects and real audit-capacity effect.
The same indexed evaluator then verifies twelve write frontiers, reconstructs
the six-mutation primary after-roots and preserves the thirteenth read-only head.
No incoming successful carrier, alleged mutation or after-root substitutes.

Canonical proof, context, private-input and indexed-transition commitments are
recomputed and compared with every signed digest/byte count. Transition bytes
retain the live format: actual mutations, result, work units, after-roots and
thirteen after-heads. The original signed envelope identity is recomputed too.

## Two different time obligations

Current processing uses the supplied actual clock bracket, work and inherited
monotonic bound. Its age/skew can be stricter than the independent scope policy.
The current deadline is **not** clipped to the old plan, scope, state-observation,
challenge or delivery expiry. Sticky real-clock checks bracket verification,
indexed evaluation, commitment work and return; no new window or budget opens.

Original validity is checked algebraically from authenticated originals: bounded
signed duration and scope deadline, original state enrollment/observation timing,
selected session/challenge/provider and delivery lifetimes, plus original database
cutoff. That cutoff must precede signed expiry and cannot precede signed issuance
by more than the original scope's skew. Future signed issuance is rejected against
the actual current clock and original policy. Historical metadata is never
supplied as `now` to a live verifier.

`write_result.live()` checks **current processing only**.
`valid_until_epoch_ns` is **original lifetime metadata**; signed plan expiry must
fit it, but current time is never compared against it as renewed permission.
These historical facts cannot authorize a new plan, reserve, SQL attempt or
token release. Independent historical key/configuration/root provenance remains
the caller's obligation. Unknown source cohorts fail closed; this does not solve
general cross-version authority resolution or lost-original recovery.

After source freeze, validation must cover expired-but-authentic originals,
current processing expiry/clock reversal, altered signatures/commitments/heads,
out-of-interval DB/state/row times, changed indexed effects and rejection by
unchanged live APIs. Those checks have not been run in this source-only batch.

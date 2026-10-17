# Native candidate response observations

Source implementation only; no builds, tests, provider contact or runtime
acceptance. This follows the opening and terminal/request exporter without
changing their closed wire profiles or adding any signer permission.

## Actual owner and sequence

`ShadowResponseAttempt` already binds the real bounded transport capture,
physical headers/body, active validation and completed active effects. It first
finalizes the actual terminal, then admits a bounded `ShadowResponseJob` and
opens its enqueue gate only after a genuine durable enqueue record. The same
worker processes the earlier request evaluation and its export first.

The response worker evaluates `evaluate_candidate_response` using those retained
response facts and the candidate plan. This is candidate-only validation: no
credential, quota, JIT, provider, or active-policy effect is added. Only its
successful `ResponseEvaluated` result and exact committed `LedgerAppend`
original reach the exporter. Error-hash/failure/unavailable records are not
exported as successful comparisons; a selected failure or uncertain export
marks the real runtime hard-unready. The existing cleanup and append ownership
are preserved, including whether a comparison terminal was actually appended.

The retained native owner advances opening -> terminal -> request observation
-> response observation. It retains the exact terminal and request receipt
hashes, not a caller sequence number or verdict. Every genuinely new observation
gets one bounded processing deadline under the original native/generation
lifetime. The original receipt time is unchanged; a consumed opening's HTTP
deadline is not reused for a long-running request. Once attempted, uncertainty
cannot reopen a phase or bypass the unresolved protected delivery head. No
replay, re-sign or second intake contact is introduced.

## Closed original and controlled consumer

`catchplate.nativeCustodyResponseObservation/v1` is exact 13 fields, adding
`request_observation_receipt_sha256` to the provenance/receipt carrier. The
existing `nativeCustodyRuntimeObservation/v1` stays exact 12. The unchanged
21-field signed receipt is phase `response`, event `response-evaluated`, signed
by the actually assigned `CustodyLedgerAppend` owner under its existing
assignment-bound production scope. No legacy Fleet envelope is fabricated.

Intake requires one already consumed opening, one actual post-dispatch terminal,
and one consumed request observation under complete authenticated batch roots.
It compares generation/ingress/request commitments, original ordered time and
ordinal, final active decision/effects, exact response facts and active validation
against that terminal. Candidate plan and disposition must equal the request
observation. The candidate validation commitment is retained unchanged. The
actual response event omits an active-plan field; intake requires null rather
than synthesizing one. A second response or changed request ID is refused.

Current assignment/load/publication/role-revocation validation, genuine receipt
signature checks, audit, exact original journal and delivery-slot consumption
remain one controlled transaction. The result9 names only
`candidate-response-observation`; it does not issue execution authority.

## Bounds and remaining work

Existing 64 KiB carrier, 16 KiB event, 256-key inventory and whole-operation
ceilings are unchanged. The fixed 2 KiB lifecycle queue surcharge already covers
the additional digest/phase; no response body is retained by the exporter or
sent to intake. Delivery contention refuses rather than silently retrying.

This connects actual request/response comparisons; it is not client-delivery
proof, complete range coverage, checkpoint or readiness. Initial full fleet
inventory and the remaining native evidence producers, complete range/checkpoint
assembly and final Setup readiness remain separate required implementation.

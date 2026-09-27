# Private OIDC activation transition

[`authority_transition_oidc_session_activation._transition_on_work`](../serverware/authority_transition_oidc_session_activation.py)
derives five ordinary business-row effects for `oidc.session.activate`: consume
the session-binding challenge, advance the credential counter, rotate/activate
the pending session, insert an authenticated encrypted-token delivery, and
append the audit event. It does not call a legacy DB helper, write SQL, deliver a
token, or report a committed activation. The result explicitly says
`activation-effects-derived` and `sessionActivated: false`.

`_full_transition_on_work` accepts the **same original inputs** and returns the
actual `core.KernelTransition`. It invokes that original-replaying business
worker once, renders each of its five effects through `core.mutation`, then
calls the genuine shared audit-capacity finalizer on the same proof-owned
context. The sixth mutation is the finalizer's full-row capacity CAS, derived
from the actual audit insertion. Missing, full, inconsistent or caller-supplied
capacity fails; this adapter never initializes or fabricates a counter.

The six mutations are sorted by the real table/key/operation ordering. Source
limits remain 16 business rows/5 mutations/128 work units and 17 total
rows/6 mutations/130 units. The full return's `work_units` **already includes**
the actual query declarations, business kernel units and framework units via
`transition_work_units`; a future planner must not finalize capacity or count
query/framework work again. Metered proof/copy/hash work stays on the original
supplied work object. The original liveness closure and earlier assertion,
delivery and processing deadlines also remain active through finalization and
the final return. No input accepts a successful effects or capacity carrier.

The private `_full_transition_with_liveness_on_work` has the same original-input
signature and returns `transition`, `live` and `valid_until_epoch_ns` for its
same-call acquisition/replay caller. Subsequent write-frontier reads, scope
cleanup and [indexed write replay](oidc-session-activation-writes.md) must recheck
that original closure and validity bound; they cannot substitute a fresh window.
The existing full-transition API still projects only `KernelTransition`.

The exact `KernelContext` contains the actual ten-field argument profile,
selected rows, original `QueryRead` records, request digest and independently
admitted database time. Private keyword inputs provide the original assertion,
old/new token bytes, original delivery envelope and independently held custody
key, expected user/session/credential/credential-record/challenge identities,
independent RP/origin/authentication/trust policy, original primary and range
proofs plus independent roots, and the existing work/window/deadline. A caller
cannot provide a successful CAS, completeness, assertion or delivery result.

The ten request fields are `session_id`, `user_id`, `credential_id`,
`credential_record_id`, `challenge_id`, `old_token_digest`, `new_token_digest`,
`assertion_digest`, `delivery_ttl_seconds` and conventional `businessIntent`.
That intent is recomputed using the real authority normalizer; it is not
permission. Token/assertion digests must match the same-call original replay.
The expected target must come from genuine retained-finalization ownership and
fresh caller admission; neither a posted locator nor these scalar pins proves
that prerequisite. The fresh activation challenge is separate from the retained
registration challenge.

The actual [activation read worker](../serverware/authority_oidc_session_activation_reads.py)
replays primary membership/nonmembership and
complete counted-index range proofs. Required empty ranges cover the new
session token and all five delivery uniqueness columns (`session_id`, old/new
token digests, assertion digest and challenge ID), plus pending trust
publications. Delivery and audit ID absences are genuine exact primary reads.
An empty SQL observation or omitted row is never substituted for these proofs.
All proofs remain relative to independently admitted roots and maintained index
population; they are not an off-host action-time currentness witness.

The business worker then calls the real [original assertion admission](oidc-session-activation-admission.md)
again on the proof-owned session/challenge/credential rows. It joins selected
active RBAC roles to the pending session's exact roles, selected trust
publication/high-water to the independent current trust policy, and row times
to the admitted database time. Role removal, changed counters, consumed
challenges, changed trust scope or expiry deny the derivation. Root, role and
trust-policy provenance are not learned from the request.

Delivery and audit IDs use the existing deterministic identity primitive with
the actual request digest and distinct `activation-delivery`/`activation-audit`
purposes. The real [delivery original helper](../serverware/oidc_session_activation_delivery.py)
authenticates the exact ciphertext against a scope derived here, with expiry
`min(database time + explicit 5–60 second TTL, session expiry)`. Ciphertext is a
separate private input, avoiding a request-digest/envelope/ID cycle; the actual
derived mutation and future plan commit its exact bytes. Its storage format is
distinct from legacy token encryption. No plaintext token appears in effects,
audit data or returned results.

The original work and dual-clock window are retained, including any earlier
monotonic cap. No new allowance, fresh expiry or delivery retry is manufactured.
Database time is independently supplied and checked against that processing
scope, not inferred from a response or advertised as a trusted clock.

Typed planner/kernel factory registration, composition of the available
[after-root/indexed write replay](oidc-session-activation-writes.md) with the
[signed-plan producer/verifier](oidc-session-activation-plan.md), cold policy/key admission, protected one-use SQL,
currentness admission and committed token delivery/recovery remain separate
required integration. The original five-effect API remains unchanged; only the
full adapter performs common capacity finalization. This source-only
worker does not make the legacy production activation route usable or complete
F08. No tests, builds or runtime validation ran. Frozen verification still needs
valid originals, tampered/omitted range and primary proofs, uniqueness conflicts,
RBAC/trust changes, replayed assertions/envelopes, expiry/clock reversal, shared
work exhaustion and confirmation that no plaintext token escapes. Full-adapter
coverage also needs missing/full/tampered capacity, the exact single audit delta,
six source mutation templates and rejection of double finalization/accounting.

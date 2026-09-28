# Actor-owned recovery grant acquisition

`control_plane_oidc_session_activation_recovery_acquisition._acquire_on_owner`
is a private context manager over the actual cold owner, actual `Request`,
immutable `recovery_bytes`, and the existing `live_window`,
`transport_deadline_ns`, `work` and `current` guard. The startup owner's private
`_acquire_oidc_session_activation_recovery_grants` facade returns this context;
it does not open a new clock, take a successful permission DTO, reuse a LIVE
activation permission or expose a recovery HTTP dispatch route.

The context enters the actual [fresh recovery actor](control-plane-oidc-session-activation-recovery-actor.md)
once, including historical target replay, old-cookie possession, current target
roles/session/credential/trust, a distinct fresh WebAuthn assertion and any
required approval. Its source-owned per-actor latch is spent before acquisition
work. The actual parent v15 `release_recovery_grant_acquisition` material supplies
the independently authenticated fixed issuer endpoint and four original byte
strings: issuer policy, historical release custody, proof enrollment and intent
enrollment. No root signing key is present in this public configuration.

## Exact original sequence

1. The journal's existing admitted index selects exactly five immutable records:
   activation claim, consume claim, release intent, release proof and completion
   hints. Actual metadata sizes are charged on the same work before bounded
   reads. No prepared ciphertext or whole consume prefix is loaded. Missing
   originals mean unavailable, not nonexecution or retry authority.
2. The selected intent is byte-equal to the freshly inspected actor target.
   The proof response's custody and enrollment are byte-equal to the independent
   parent originals. Its `proved` marker is only a required framing state, never
   proof authority. The unsigned hints decoder supplies the encrypted 100-byte
   envelope, not authenticated effects, dates or execution status.
3. Genuine independent policy admission authenticates the exact policy identity,
   historical custody and enrollments. Its delivery scope and intent digest must
   match the freshly authenticated actor target. The issuer request prefix7 is
   `(recovery-purpose, proof, proof-enrollment, intent, intent-enrollment,
   old-token64, encrypted-envelope100)`. The old token stays request-local.
4. The new durable attempt is keyed by finalization locator, opaque activation
   association locator, genuine release-intent identity and independently signed
   issuer-policy identity. `MAX_CLAIM_IO_BYTES` and conservative hash work are
   charged before the actual claim callback. The claim must succeed before any
   issuer socket contact. Same-policy existing or recovered claims always deny;
   a genuinely fresh independently authorized policy is a separate explicit
   attempt, never an automatic retry or renewal of old authority.
5. The [.204 finite client](control-plane-oidc-session-activation-release-recovery-grant-acquisition.md)
   genuinely re-admits the independent originals, performs one bounded exchange,
   and admits the returned client authorization, server bootstrap and canonical
   outcome through the actual original-only verifier. That verifier independently
   authenticates historical proof/intent, possession and envelope commitments;
   hint data cannot authorize them.
6. Only **after genuine admission**, the exact returned raw3 is precharged with
   `_append_io_bytes` and retained through the actual journal/client facade.
   The opaque codec does not authenticate signatures. Malformed, missing or
   rejected responses can leave a spent claim without a retained triple; this
   path does not claim to retain every pre-admission response.

The yielded private `_RecoveryAcquisition` exposes only guarded `originals`
and `current()`, not the admitted material or a reusable permission. Genuine
policy and response guards remain attached under the same original work,
PID/thread, owner resources and narrowing clocks. The ancestor callback invokes
only the actual actor guard; it never cycles through a child guard or recursively
selects records under the journal I/O lock. Normal or exceptional context exit
revokes the continuation and clears its actor reference before the actor's own
cleanup. Byte copies alone provide no recovery authorization.

## Capacity and remaining boundary

Before new record reads, this phase reserves eight closed 4 MiB parent-input
footprints, four measured fixed actor-graph footprints, the held historical
intent/key reserve, and three maximum encoded five-record footprints. The
32 MiB parent reserve plus the less-than-25 MiB fixed selection reserve leaves
positive capacity for bounded real inputs; individually valid large inputs can
still fail closed. Measurement visits only a fixed table of actual owned scalar
and collection graphs, without serializing them or traversing arbitrary objects.
After selection, actual immutable original sizes replace the selection maxima.

The caller then reserves its additional genuine policy/capture inventory and
passes the complete newly held amount as `_additional_original_bytes` to the
finite client. That exact nonnegative integer only consumes the existing 64 MiB
budget and tightens the reply cap before body allocation. The client's eight
reply footprints also reserve subsequent durable encoding/publication/readback;
no new allowance is granted between those phases. Capacity reservation and actual
cumulative work charges remain distinct. These are original/capture bounds,
not Python allocator-overhead or process-memory guarantees.

**Required follow-up before freeze:** the earlier, unchanged pre-actor
finalization subject replay loads preparation/reservation/finalization and
completion-evidence originals before its existing aggregate sum check. Its
combined preallocation integration with already held parent/actor input remains
open. This new acquisition-phase reservation does not repair or waive that
earlier loader boundary.

Recovery-worker staging, genuine checkpoint-one private outcome observation,
protected recovery exchange, current-auth/cookie completion and a public
recovery dispatch route remain open. A reconstructed canonical outcome and its
fresh signed expectations are not proof that the private store contains it.
Prior-stage completion recovery remains separate; neither activation nor SQL
may be repeated. See the [full public recovery boundaries](oidc-session-activation-public-recovery.md).
Source only: unbuilt, unexecuted and unprovisioned.

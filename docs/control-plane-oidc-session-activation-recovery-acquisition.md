# Actor-owned recovery grant acquisition

`control_plane_oidc_session_activation_recovery_acquisition._acquire_on_owner`
is a private context manager over the actual cold owner, actual `Request`,
immutable `recovery_bytes`, and the existing `live_window`,
`transport_deadline_ns`, `work` and `current` guard. The startup owner's private
`_acquire_oidc_session_activation_recovery_grants` facade returns this context;
it does not open a new clock, take a successful permission DTO, reuse a LIVE
activation permission or expose a recovery HTTP dispatch route. Before yielding,
it stages its exact retained server original once through the private root
receiver connection; a staged ACK is not recovery-worker readiness.

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
7. `_acquire_on_owner` itself invokes `active.stage_release_worker()` after
   durable retention and before yielding. This source-owned method accepts no
   caller bytes or endpoint, selects only its own raw3 element 1, requires the
   genuine RECOVERY server profile, and spends its local latch before contact.
   The fixed root staging endpoint uses the independently admitted policy's
   launch timeout. One [raw2/ACK2 exchange](oidc-session-activation-release-recovery-delivery-transport.md)
   compares the actual outgoing server-original identity and requires owned
   normal close. The method returns `None`, never a readiness or permission
   result. No repeated call, recovered-context resume or automatic retry exists.

The acquisition-only facade still yields after grants and staging; it does not
automatically exchange or return a token. The private `_RecoveryAcquisition`
exposes guarded `originals` and `current()`, not the admitted material or a
reusable permission. Staging is already spent when the context is yielded;
attempting it again fails. Genuine
policy and response guards remain attached under the same original work,
PID/thread, owner resources and narrowing clocks. The ancestor callback invokes
only the actual actor guard; it never cycles through a child guard or recursively
selects records under the journal I/O lock. Normal or exceptional context exit
revokes the continuation and clears its actor reference before the actor's own
cleanup. Byte copies alone provide no recovery authorization.

## Separate protected recovery context

`_recover_on_owner(owner, *, request, recovery_bytes, live_window,
transport_deadline_ns, work, current)` enters that same acquisition context,
calls its one-shot `exchange_token()` and yields only after genuine response
verification. The actual startup owner exposes this through the separate
`_recover_oidc_session_activation_token` facade with the same original kwargs.
The existing `_acquire_oidc_session_activation_recovery_grants` facade retains
its grants-and-staging-only behavior. Neither facade supplies a fresh processing
window, a successful permission DTO, current-auth evidence or an HTTP result.

Exchange requires the explicit successful-stage marker, not merely the spent
staging latch. The context spends its exchange latch before the actual exchange
helper, which derives the request from the retained intent/proof/encrypted
hints and actual actor's ephemeral old token. The exchange helper owns the
durable token-free attempt before protected socket contact and genuine original
response admission. The method itself returns `None`; only the guarded
`token_bytes` accessor exposes the genuine exact 64-byte token, and only while
the actual authorized context remains active after successful exchange.
No request, old token, recovered token or response body is added to the journal.

The actual receiver retains its final narrowed guard through the private
`_retain_receiving_current(current, window, bound)` hook, exactly once during
exchange. `_parent_current` and `_parent_continuity` retain the original actor,
policy, acquired-grant, clock and resource restrictions but never call this
response child. The outer `current()` checks parent → genuine response child →
parent; the child can therefore retain its actual ancestors without a cycle.
The original scope/lifetime identities and token/guard identities are held by
source-owned seals. Narrowing preserves the original clock opening and cannot
increase its deadline or allowance.

Any exchange or retained-guard failure poisons the context and clears its token
and receiving guard. Repeated exchange is forbidden. Normal or exceptional exit
also clears them and revokes access before actor cleanup; keeping an immutable
byte copy cannot carry this authority beyond the live context. This source path
does not perform fresh current-auth, replace a cookie, send an HTTP success or
make a recipient-acknowledgment claim. Those require a separate guarded public
delivery integration.

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

Staging retains that same input/capture reservation and eight exact returned
triple footprints, then reserves additional bootstrap hashing/chunk copies,
fixed headers and all ACK buffers before hashing or socket contact. This may
reject otherwise valid large originals; it cannot borrow another 64 MiB budget
or replace the actor ledger after acquisition. Small bounded originals retain
positive capacity under the existing fixed ceiling. A stage failure can leave
the durably admitted triple, but the same policy attempt remains spent and the
context yields nothing. The ACK itself is not an authority record or token and
is not persisted as a success marker.

The earlier pre-actor replay now uses the
[combined historical reader](control-plane-registration-finalization-completion-history.md).
It checks the complete selected metadata inventory before the first body read
and reads each file once. The actor and historical inspector pass their held
request/token/configuration representation counts into the subject's tightening
allowance; the subject also reserves cold-parent, enrollment and replay space.
This closes the earlier post-load aggregate-check gap in source. Both phases
still use one cumulative work allowance, and neither claims a 64 MiB process
heap bound or runtime verification.

The staged ACK does not establish worker readiness or genuine checkpoint-one
private outcome observation. The separate recovery context now connects the
protected exchange and genuine response verifier; this is source integration,
not observed store recovery, runtime delivery or recipient acknowledgment.
Fresh current-auth/cookie completion and a public recovery dispatch route remain
open. A reconstructed canonical outcome and its fresh signed expectations are
not proof that the private store contains it.
Prior-stage completion recovery remains separate; neither activation nor SQL
may be repeated. See the [full public recovery boundaries](oidc-session-activation-public-recovery.md).
Source only: unbuilt, unexecuted and unprovisioned.

# Historical registration completion admission

[`authority_registration_completion_history._verify_on_configuration`](../catchplate/authority_registration_completion_history.py)
authenticates a completed registration-evidence operation from the complete
original exchange, even after its original execution controls expire. It
returns authenticated completion/state originals and their actual content IDs,
**not permission to execute, retry SQL, finalize a credential or recover on
behalf of a present caller**. This source is unbuilt and unexecuted.

## Required original and independent scope

The keyword-only API requires the actual grant raw10, reservation raw3 and
completion raw4; the three original caller/grant/current-root enrollments;
independently admitted configuration digest/payload, generation/runtime cohort
and root key; independent expected pending sequence/head/fence; and the caller's
existing `live_window` and cumulative `work`. Optional
`transport_deadline_ns` only narrows that processing bound.

All individual/planning-group carriers and the complete 64 MiB original
inventory are held before native callbacks. Configuration graphs are detached
before verification. No key, expected checkpoint or request identity comes
from the completion response merely to make it match. An uncertain raw4 returns
no authenticated result.

Planning, caller and grant admission is shared with the private
[historical exchange verifier](registration-history-exchange.md). That helper
needs only the original raw10 and independent scope, so it can support historical
retained-subject inspection before a reservation or completion exists. This
completion wrapper still bounds the full raw10/raw3/raw4 inventory together and
requires the remaining original pending/completion verification.

## Genuine verification chain

```text
independent configured keys + complete original raw10/raw3/raw4
    -> verifier-signed historical planning request and exact body commitments
    -> planner-signed historical response and request/raw3 commitments
    -> full plan proof/semantic/root replay and bounded historical observations
    -> original caller signature and dedicated grant authorization
    -> complete before/after-vector replay and every original grant claim
    -> exact original request, operation, enrollment and interval joins
    -> genuine pending/plan/grant + completion/state-original verification
    -> unchanged completion/state originals and authenticated content IDs
```

The [historical request](historical-evidence-planning-request.md) verifier
authenticates the original control before decoding its context and binds its
complete inputs. The [historical response](historical-evidence-planning-response.md)
verifier authenticates all original bodies, including the exact request control.
The duplicated request/response input bytes must be identical.

The [history admission](historical-evidence-planning-history.md) performs real
plan-signature, proof, input-semantic and root-effect replay. It derives history
from the authenticated request, independent configured policy and only three
bounded signed planner observations. Exact canonical context and signed plan
times must agree. Those observations are authenticated claims, not independent
database-clock or current-root authority.

The [historical caller verifier](registration-historical-authorization.md)
authenticates the original distinct caller purpose. Its request/operation and
generation must agree with the genuine planning request and actual configured
generation. The real historical grant verifier binds the dedicated authorizer,
original caller-authorization identity, enrollments, database/generation and
request/operation. Grant issue/expiry must remain inside its original caller
and planning authority intervals. The shared exchange verifier also invokes the
actual complete-vector plan replay, not merely a before-vector hash comparison.
Every derived grant claim must match: original frame bytes/counts, request and
operation, retained-record/plan/result identities, complete before/after-vector
identities, original plan interval and signed snapshot/capability identities.
Unaffected vector descriptors remain preserved by the existing replay engine.

Finally the actual [completion response verifier](registration-completion-response.md)
replays the original pending plan/grant and verifies original completion/state
signatures, exact marker/vector/snapshot/result scope and canonical embedded
observation. It uses independent pending inputs, not a response-appointed head.
No prior successful replay object replaces these original bytes.

## Historical time is not renewed authority

The old request, plan, caller and grant expiry may be in the past. Their
internally authenticated positive intervals, configured age limits and mutual
ordering remain mandatory. In particular, the signed planning response cannot
postdate the original plan expiry. Future-issued controls/observations beyond
configured skew fail against the current processing clock.

The current work window is supplied by the caller and remains unchanged across
all phases, with sticky wall/monotonic checks and any shorter inherited deadline.
It is never constructed from a historical issue timestamp. No current instant
is replaced by an old time to make a live verifier pass, and existing live
execution verifiers are untouched. A fresh processing window authenticates old
records; it cannot revive their power to perform an operation.

The result is the existing private four-field completion-original observation:
request bytes, state receipt bytes and their two actual framed identities.
It carries no mutation, executable grant, packet-ID claim or currentness lease.

## Remaining integration

This verifier alone is not a deployed or public recovery workflow. Public
execute/completion actions retain their live ownership and original-authorization
requirements. The separate [completion recovery path](registration-completion-recovery.md)
integrates historical ownership, dedicated public recovery-purpose admission and
bounded reconciliation in this same source-only batch; those checks are not
provided by this verifier. Credential finalization, action-time currentness and
cross-generation historical authority resolution remain separate. No production
acceptance gate is closed.

Deferred frozen verification must exercise valid expired originals against live
rejection; altered signatures, body commitments, generation, keys and scope;
unrelated authentic exchanges; impossible original timing; changed complete
before/after-vector descriptors or grant claims; exact pending joins;
malformed/uncertain completion; cumulative work exhaustion,
window expiry and clock reversal; and unchanged SQL/live rejection behavior.
No such tests or runtime verification ran in this source batch.

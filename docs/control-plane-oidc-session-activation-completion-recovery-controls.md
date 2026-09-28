# Historical public completion controls

`control_plane_oidc_session_activation_completion_recovery_controls.py` connects
the genuine fresh completion-recovery actor to retained activation or consume
controls. It admits original public signatures and an acknowledged historical
reserve. It does not open ciphertext, replay private proofs, establish SQL
commit, authorize SQL, release a token or renew an expired execution interval.

## Fixed same-actor entrypoint

```text
_admit_on_actor(actor, *, _additional_original_bytes=0) -> _CompletionControls
```

Only the actual active, authorized `_CompletionActorScope` is accepted. The
orchestrator must already have irreversibly spent that actor's completion
recovery latch. No request may supply a successful target, marker, expected
scope, public key, profile selector or previously admitted controls object.
The actor owns the original work/window, genuinely admitted historical target,
old-token possession and independent completion-recovery configuration.

The target retains its actual selected historical activation `authority` (R0).
Activation completion and existing non-completion purposes keep that authority.
Consume-profile completion instead uses the actor's exact preselected consume
history (R1), independently admitted before fresh actor binding. Its selected
execution policy, root, configuration, original interval and completion pins
are separate from the target's activation association. Packet identity,
caller-authorization identity and pending `(sequence, headDigest, fence)` come
from the selected completion scope. The current parent independently enables the profile;
only its current endpoint supplies routing. Old endpoint metadata cannot grant
transport access. Without history, the existing current material is unchanged.
The exact caller-original identity is compared before deeper control admission.
The packet pin remains an independent expectation: these public records and
the activation raw4 response do not attest a private packet's identity.

The controls preserve `authority` as R0 and retain `consume_authority` as the
exact selected R1 object only for this distinct completion path. Neither is an
incoming result accepted instead of originals: caller, plan, grant and reserve
signatures are still genuinely verified under R1 below. The activation claim's
authorization-enrollment association is still checked against R0. Missing or
ambiguous cold authority cannot fall back to a root from a journal record.

## Exact retained inventory

The direct charging custody loader returns fixed tuple10:

```text
activation claim, consume claim or None, prepared, exported or None,
authorized or None, grant, reserved, completion or None, hints or None,
SQL claim
```

For separately selected consume completion, this fresh tuple10 must match the
pre-actor selector's immutable activation-claim association and consume
claim/prepared/authorized record commitments at positions 0/1/2/4. The source
matcher also checks source, finalization and global consume-slot associations.
Selection is not a cache of successful control admission; the subsequent
signature and target checks remain mandatory on these freshly loaded originals.

Activation requires its prepared raw5, grant raw1, reserve raw3 and irreversible
SQL claim. Consume additionally requires its own claim, prepared raw6, exported
raw7 and caller-authorization raw1. The consume prepared response contains the
typed request, scope and signed plan; only export retains the ciphertext bound
by the actual caller and grant. Prepared/export originals must correspond
exactly. An uncertain preparation or absent required record cannot establish
the dispatched control prefix. SQL-outcome bodies are neither loaded nor used
as execution evidence. The zero-original SQL claim is required association
data, not evidence that SQL succeeded.

Existing completion/hints remain immutable observations. A complete old response
is exposed separately from `prior_completion`, because an acknowledged consume
raw4 can survive before its hints are retained. The response owner can obtain
raw6 only through its one completion-only attempt and must preserve the exact
acknowledged first four originals. Earlier uncertainty remains separate data;
it is never overwritten or promoted to an authenticated outcome.

## Original admission, not authority renewal

Activation uses the actual historical caller and execution-grant verifiers.
Consume uses its genuine enrollment, canonical caller/plan/grant codecs and
signature domains in a separate public historical composition. This adds no
historical mode to the live consume caller or private replay implementation.
Both lanes join the exact typed request to the actor's authenticated
user/session/credential/challenge and old/new token commitments. Neither old
nor recovered plaintext token is returned or retained here.

Original plan/caller/grant/reserve issue and expiry remain ordered and contained
within the selected evidence authority's original archive interval. Activation
controls use R0; separately selected consume controls use R1 without borrowing
the activation target's keys. The independently pinned target identity and
activation authorization still join the same original global consume slot.
Unknown, ambiguous or absent archived completion pins have no current fallback;
source/enrollment age ceilings and future-issue restrictions still apply.
The existing processing window is only narrowed to the genuine caller, grant
and current-root age/skew ceilings and original scope restrictions. Its opening
samples, work and clock floors remain unchanged; the returned continuation owns
the final narrowed window and bound, never an expired execution deadline used
as a new clock. The fresh processing window is not substituted for an old interval. Enrolled
root, caller, planner, grant-authorizer and state keys are admitted from the
selected original historical scope. Public ciphertext framing and signed commitments are
not claims of successful AES opening or private replay.

The actual historical current-root request and reservation verifiers authenticate
reserve, snapshot and state ACK against the independently configured predecessor.
The ACK must match the selected historical scope's exact pending tuple. Grant, snapshot, request,
full before/after vectors and fixed operation all agree before constructing the
source marker. This does not establish that this is today's latest pending head.

## Sealed continuation and capacity

The private frozen `_CompletionControls` retains the actual actor, SQL raw8
controls, before/after bytes, marker, enrolled state original/root key,
configuration pins, exact activation authority and optional separate consume
authority, work/window/deadline, total reservation and prior response
originals. Consume's expectation field is canonically regenerated from its
retained typed-request/scope/journal originals and authenticated commitments;
it is not a caller-supplied authority template.

`_require_controls(value)` and `value.current()` check the exact private
construction, immutable field references, every marker scalar and the still-live
authorized actor, identical target authority and exact sealed consume selection.
Both selected authority guards remain siblings of genuine admission children, preserving archive authorization
without feedback into their ancestors. Original owner/key/enrollment identities, work limits and
both clock floors remain guarded. Child historical guards receive only the
base ancestor; the response guard is never fed back into its own parent.
Closed actors cannot use this continuation. The orchestrator separately owns
the durable phase-only attempt and sole socket latch; controls alone cannot
authorize a network call.

Before the full control body read, the helper subtracts the actor target's
existing reservation, or replaces it once with the consume selector's total
reservation (which already includes that target and upstream future capacity).
It then reserves caller-supplied additive transport/journal capacity,
four cold-enrollment representations, fixed metadata, vector and expectation
headroom from the existing 64 MiB bound. It passes three eighths of the remainder
to the loader, whose exact metadata preflight covers three selected encoded
representations plus 16 KiB. Eight selected-original footprints remain reserved
for loading and subsequent bounded captures. The returned reservation includes
all of these held phases; it is not another allowance or a process-heap bound.
The target already retains the archived completion configuration within its
existing cold-original reservation; that inventory is not counted as a new
allowance here. Coordinator transport/publication headroom must reach the
actor before its target's first historical body read.

The receiving helper chooses the explicit R1 root/state/completion pins when
`consume_authority` is present, while preserving current endpoint routing. Its
actual raw4/raw6 verifiers already consume those explicit enrolled originals,
pending tuple and marker. Configuration-digest framing and durable phase-only
attempt slots are unchanged; changing authority cannot create another attempt.

New completion statements are independently signed historical reconciliation,
not renewed execution. Their issue time need not fall inside the old execution
interval: the receiving helper checks its genuine state enrollment, exact old
marker/pending binding, observation and current processing/future-clock guards.
These controls alone authorize no fresh effect. The fresh consume action still
requires its separate explicitly configured parent-v21 input bridge and fresh
WebAuthn/approval-bound actor; the actor can now admit that distinct purpose
without borrowing this completion permission. Historical intent/proof signing,
release-grant acquisition and token release retain their current-only gate and
need their own independent original joins.

See the [parent configuration](control-plane-oidc-session-activation-completion-recovery-bootstrap.md)
for fixed profiles. Completion-only exchange, genuine response admission and
separate reconciliation are composed by their actual owners under this same
fresh actor. Source integration supplies no build, test, runtime, provisioning
or production-delivery evidence.

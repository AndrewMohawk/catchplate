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
old-token possession and independent signed-parent v16 recovery configuration.

The selected endpoint, packet identity, caller-authorization identity and
pending `(sequence, headDigest, fence)` come from that actual parent. The
exact caller-original identity is compared before deeper control admission.
The packet pin remains an independent expectation: these public records and
the activation raw4 response do not attest a private packet's identity.

## Exact retained inventory

The direct charging custody loader returns fixed tuple10:

```text
activation claim, consume claim or None, prepared, exported or None,
authorized or None, grant, reserved, completion or None, hints or None,
SQL claim
```

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

Original plan/caller/grant issue and expiry remain ordered and contained;
source/enrollment age ceilings and future-issue restrictions still apply.
The existing processing window is only narrowed to the genuine caller, grant
and current-root age/skew ceilings and original scope restrictions. Its opening
samples, work and clock floors remain unchanged; the returned continuation owns
the final narrowed window and bound, never an expired execution deadline used
as a new clock. The fresh processing window is not substituted for an old interval. Enrolled
root, caller, planner, grant-authorizer and state keys are admitted from the
actual parent originals. Public ciphertext framing and signed commitments are
not claims of successful AES opening or private replay.

The actual historical current-root request and reservation verifiers authenticate
reserve, snapshot and state ACK against the independently configured predecessor.
The ACK must match the parent's exact pending tuple. Grant, snapshot, request,
full before/after vectors and fixed operation all agree before constructing the
source marker. This does not establish that this is today's latest pending head.

## Sealed continuation and capacity

The private frozen `_CompletionControls` retains the actual actor, SQL raw8
controls, before/after bytes, marker, enrolled state original/root key,
configuration pins, work/window/deadline, total reservation and prior response
originals. Consume's expectation field is canonically regenerated from its
retained typed-request/scope/journal originals and authenticated commitments;
it is not a caller-supplied authority template.

`_require_controls(value)` and `value.current()` check the exact private
construction, immutable field references, every marker scalar and the still-live
authorized actor. Original owner/key/enrollment identities, work limits and
both clock floors remain guarded. Child historical guards receive only the
base ancestor; the response guard is never fed back into its own parent.
Closed actors cannot use this continuation. The orchestrator separately owns
the durable phase-only attempt and sole socket latch; controls alone cannot
authorize a network call.

Before the first selected body read, the helper subtracts the actor target's
existing reservation, caller-supplied additive transport/journal reservation,
four cold-enrollment representations, fixed metadata, vector and expectation
headroom from the existing 64 MiB bound. It passes three eighths of the remainder
to the loader, whose exact metadata preflight covers three selected encoded
representations plus 16 KiB. Eight selected-original footprints remain reserved
for loading and subsequent bounded captures. The returned reservation includes
all of these held phases; it is not another allowance or a process-heap bound.

See the [parent configuration](control-plane-oidc-session-activation-completion-recovery-bootstrap.md)
for fixed profiles. Completion-only exchange, genuine response admission and
separate reconciliation are composed by their actual owners under this same
fresh actor. Source integration supplies no build, test, runtime, provisioning
or production-delivery evidence.

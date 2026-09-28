# Completion-only exchange and public historical response admission

`control_plane_oidc_session_activation_completion_recovery_exchange.py` consumes
only the actual fresh completion actor's source-owned historical controls. It
does not accept an activation permission, a caller-supplied successful result,
private AES custody, a token or an unsigned packet as authority.

For admitted configuration history, those controls retain the genuine target's
selected archive authority. The exchange checks the exact selected root and
state-enrollment originals and independently admitted packet/authorization/
pending pins; only the enabled worker endpoint stays current. It never reads a
replacement root or completion profile from the current parent or from returned
data. The controls guard retains the archive and fresh actor through all work.

The root orchestrator first publishes the separate irreversible completion
attempt. `_exchange_on_controls` requires that exact active claimed attempt and
spends its one-use socket latch before contact. Activation selects the existing
dispatch-v2 endpoint; consume selects the existing release-hints-v3 endpoint.
Both requests contain only the fixed purpose and exact historical caller
authorization. The worker independently compares that original to its root-held
authorization and uses its own packet/pending pins. This is not SQL resubmission.

The guarded transport uses the original work, current guard and absolute
deadline through peer checks, length preflight, EOF and normal socket close.
Activation returns `(status, complete identity, complete original, state ACK)`;
consume adds the unsigned packet-digest and encrypted-envelope descriptor hints.
The root retains those exact opaque originals in the separate reconciliation
namespace before interpreting their selector or signatures. Old uncertainty is
never replaced and a claim never permits automatic retry.

An existing claim cannot contact the worker again. A separately retained
response may instead be boundedly reselected under a fresh actor, with its
exact source, association and configuration pins checked before this same
genuine response admission. Stored bytes alone do not supply authority; an
absent or uncertain response remains terminal.

`_verify_on_controls` admits the actual historical completion-role signature and
state acknowledgment against independently admitted enrollment/root/pending
scope. It joins the complete statement and canonical signed observation to the
genuine historical marker and full after-vector. Historical expiry is not
renewed into fresh control authority: only the current processing age/skew can
narrow. A future-issued statement or uncertain response is refused. Existing
acknowledged originals must match exactly, including an old consume raw4 whose
separate hints were not retained.

The old caller/plan/grant/reserve statements must fit the independently admitted
historical execution interval. A new completion statement and its state ACK are
not forced into that old interval: their own genuine enrollment, signed marker,
original processing window and future-issue checks remain required. This does
not turn an expired historical permission into a live permission.

The raw4 wire contains no packet identity. A matching consume hint is only a
consistency check against the independent packet pin; hints remain unsigned
data, not proof of private replay, release authority, latest state or an active
session. All private packet/AES/commit admission stays in the configured worker.

Before the first historical target body read, `_exchange_reservation(profile)`
contributes a fixed conservative reserve for request/response buffers, repeated original
captures, enrollment/key representations, signed observation and vector copies.
The actor target carries it into the controls loader exactly once, inside the
same 64 MiB representation ceiling; journal I/O is reserved separately. This is
not a heap/RSS guarantee or fresh
work allowance. Pure signature admission is bracketed by the original guard;
native transport operations use its existing per-operation guarded path.

The returned genuine receiving guard remains a separate child through normal
actor/trust cleanup; it must not be attached back into its own controls ancestor.
No closed-actor fallback is provided. Public historical success requires the
orchestrator's successful normal cleanup and does not release a token or cookie.

This completion-only historical-authority connection does not extend the later
fresh consume, intent/proof or token-release producers to archived authority.
Those separate current-scope continuations already re-admit retained originals
under distinct fresh permissions; they do not inherit this actor. The recovery
worker also requires
an independently authorized existing checkpoint-one outcome: reconstructing an
outcome, or missing local records, proves neither existence nor an empty slot.
No SQL retry, fabricated delivery dates or automatic first release is implied.

This source has not been built, executed or provisioned as part of this change.

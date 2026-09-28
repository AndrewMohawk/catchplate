# Original consume selection before completion binding

The original activation authority (R0) and original consume authority (R1)
need not be the same root or configuration. This source slice independently
selects R1 from retained, genuinely signed consume evidence before a fresh
consume-completion actor binds its authorization request. It creates no
execution, release, retry or migration permission.

## One bounded evidence prefix

`load_oidc_session_activation_completion_recovery_consume_prefix` reads only
the activation claim, consume claim, prepared consume raw6 and authorized raw1.
It uses the existing fixed completion metadata inventory to require the exact
original dispatched association, but does not read SQL outcomes, completion
outcomes, export/grant/reservation bodies or the full ten-record control set.
No new record family, slot, write or source revision is introduced.

The loader preflights three actual encoded footprints plus 16 KiB before the
first selected body. Native immutable-file checks and direct metering use the
caller's original work and base-only guard. Expected missing or incomplete
history is unavailable; it never establishes that an earlier effect did not
happen. Corrupt associations retain the existing journal refusal behavior.

## Independent authority, exact later association

The private selector accepts only the actual owner and same-call R0 target.
It joins the claims to that target's finalization, activation authorization
and original enrollment. The prepared signed plan and original consume caller
authorization then enter the consume-history resolver. That resolver must
authenticate its independently selected current or archived R1 scope; no
posted root, successful-result carrier or fallback to R0 supplies authority.

`_ConsumeRecoverySelection` is privately constructed and identity-sealed. Its
retained commitments cover every activation-claim scalar and all three
consume record digests. `_match_controls_on_selection` checks those exact
commitments against positions 0, 1, 2 and 4 of the later bounded full-control
read before genuine grant, reservation and completion admission. This is a
DATA association check, not a substitute for those signature checks. The
selector never loads that full tuple itself.

## One original lifetime and capacity

Before the first prefix body, the selector retains the target's complete
reservation, any additional tightening, the resolver's measured extra cold
and decode captures, and fixed metadata headroom. A three-eighths remaining
loader allowance reserves eight actual encoded prefix footprints for retained
originals and subsequent admission. The complete total remains inside the
same 64 MiB ceiling. The returned `original_reservation_bytes` includes the
target and additional allowance once: later controls replace the target base
with it, never add both. `original_bytes` also includes the target originals.

Original owner/work identities, R0 target liveness, source clock floors and
the independently narrowed R1 guard remain live through actor binding and
later admission. The selector's ancestor never calls its selected child or
reacquires the journal lock. No old issue or expiry is retimed. Routing remains
the separately enabled current completion endpoint; original R1 completion
pins do not authorize another endpoint or effect purpose.

This is unbuilt, unexecuted source integration, not pilot or production
validation and not evidence of a successful historical SQL effect.

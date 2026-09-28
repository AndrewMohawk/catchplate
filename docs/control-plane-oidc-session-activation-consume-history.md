# Independently selected consume evidence authority

`control_plane_oidc_session_activation_consume_history.py` selects the authority
of an already signed consume caller and plan before fresh completion-recovery
actor binding. The retained activation target keeps its own R0 authority. It
does not supply, imply or replace consume evidence authority R1.

## Independent selection

`_scope_on_owner(owner, *, authorization_bytes, plan_bytes, window, bound, work,
current)` accepts only the two immutable originals and the actual startup owner.
Its closed locator is configuration digest, generation digest and the dedicated
consume authorization-enrollment digest. The locator chooses a key, not an
admitted result.

The helper classifies the locator against both the genuinely admitted current
parent and the existing activation-history inventory. An exact current match is
allowed alongside unrelated old history; an overlapping current/archive match,
multiple archived matches or an unknown locator fails closed. The new cold
`_lookup_consume_on_work` is separate from activation and release-intent lookups.
No new parent schema, trust catalog, posted key or current-root fallback is added.
Archived scopes retain their existing mandatory exact consume-execution profile.

Before returning, the helper genuinely re-admits the selected caller, grant and
state enrollments under R1, verifies the original caller signature and its exact
independently configured completion authorization digest, and verifies the signed
consume plan under the independently configured consume planner key and
measurement. Disabled consume-completion configuration is rejected before fresh
approval. Caller request/operation/configuration and exact signed-plan identity
must agree. Both complete original intervals must fit the independently admitted
current binding interval or selected archive snapshot. The archive receipt comes
from the admitted cold scope, not a record-supplied root or a substituted consume
planner receipt. Canonical originals and supported source contracts stay exact.

This selection is not complete private plan replay or execution permission. The
subsequent completion controls independently re-admit the retained original
caller, grant, reservation and pending state under the selected R1 scope, while
retaining the separate R0 activation association.

## Lifetime and capacity

The private `_SelectedConsumeHistory` contains configuration payload/digest,
generation, runtime role identities, R1 root, consume execution, completion pins,
original authority interval, actual `live` guard, and narrowed `window` and
`deadline_ns`. Its source-owned references and configuration graphs remain
identity/content checked. Original evidence expiry is checked algebraically;
current processing retains the same work, original clock floors and archive
authorization, with restrictive caller-policy age/skew narrowing. An expired
original is never retimed into a fresh launch.

`_capture_reservation_on_owner` returns only the additional capture reservation:
eight times the largest candidate enrollment-original sum, largest candidate
activation-planner original, caller maximum and signed-plan maximum, plus
128 KiB fixed metadata. Actual planner-original lengths bound the selected
configuration/generation/runtime graph copies. Already held parent/archive/target
originals are not counted as a new allowance. The bounded prefix selector reserves
this before its first record body and adds the retained record representations
under the unchanged 64 MiB aggregate ceiling. These are conservative
representation bounds, not a process-heap claim.

See [the complete completion-selection connection](control-plane-consume-completion-history-selection.md)
for pre-actor selection, current-endpoint routing, later full control admission
and unchanged durable completion/reconciliation slots. This source has not been
built or executed; historical intent/proof/release authorities, older-source
adapters and production acceptance remain separate work.

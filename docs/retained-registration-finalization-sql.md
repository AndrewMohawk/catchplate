# Retained finalization SQL execution

The [retained facade](../serverware/control_plane_registration_finalization_handoff.py)
connects separately authorized public execution to the real cold SQL caller.
This is source-only: unbuilt, unexecuted, unprovisioned and not independently
verified. SQL commit observation is not signed current-root completion or OIDC
session activation.

## Ownership is replayed, not inferred from a locator

`inspect_retained_finalization_sql_subject(local_digest)` returns seven bounded
subject scalars for the [public permission binding](public-registration-finalization-sql.md).
The locator identifies an actual retained finalization grant, not the evidence
grant or an older preparation-only plan. The actual reservation inspection
helper authenticates the full finalization authorization, plan and grant;
replays its associated evidence/signer ownership and acknowledged evidence
completion; reconstructs the entire request from that same signer; and compares
the original finalization inputs. A local association or historical enrollment
mode does not supply present ownership or permission.

`execute_retained_registration_finalization(local_digest, *, expected_user_id,
expected_session_id)` repeats this inspection under the actual cold owner lock.
Its expected scalars come from the handler's independently authenticated current
actor/session, not a posted subject or an earlier inspection object. One work
budget and original window cover replay, dispatch and acceptance. The window
can only narrow to the held originals' expiry and original transport deadline.

The retained reservation must share the exact source and grant association.
The facade compares the reread raw10 to its genuine ownership replay, adds the
retained reserve/snapshot/acknowledgment raw3, and bounds the complete inventory
including underlying evidence/signer/completion/enrollment originals. Historical
source/configuration/key changes do not silently gain current authority.

## Claim, send, retain, then interpret

The [private caller](control-plane-finalization-sql.md) requires both the local
locator and raw13. It rereads and byte-compares the actual complete association,
then genuinely admits the original pending scope against independent root pins.
Only after those checks does the actual journal durably publish the local
`sql-claimed` record. The claim is nonrepeatable; it is never cleared, including
after a failure before any network bytes were sent.

The worker independently owns its protected SQL attempt. That separate remote
attempt does not replace the caller's durable dispatch guard. One socket exchange
is allowed, and a bounded returned raw4 is retained as an opaque observation
before marker or invocation-lifetime acceptance. This ordering preserves an
uncertain, semantically mismatched or subsequently expired response without
turning storage into execution permission. Journal owner/PID/descriptor/byte
bounds still apply; failed publication is not claimed as successful retention.

The first exact outcome cannot be overwritten. Missing outcome bytes never
prove that nothing was sent or committed. The [separate record domain](control-plane-custody-journal.md)
does not widen evidence SQL records or admit a success token.

Only `observed-commit`, with all eighteen marker fields compared to the genuine
original-derived expectation and final original-lifetime checks passed, returns
`(local_digest, raw4)`. It remains an unsigned local observation. Uncertain
responses and ordinary failures raise `RetainedFinalizationSqlOutcomeError`
with only the submitted locator and static text; cancellation propagates.

## Remaining boundary

The public action and seventh portal control require a separate present
execution purpose. Neither grant preparation nor reservation auto-chains into
SQL. Separately admitted finalization completion/recovery and OIDC activation
remain unfinished; evidence-completion recovery cannot reconcile this different
operation. Static root pins and local journals do not provide live off-host
currentness or hostile-root rollback protection. All six production gates
remain open.

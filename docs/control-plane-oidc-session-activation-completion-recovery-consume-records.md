# Guarded consume preparation after activation completion

This .215 source continuation reuses the existing global consume target and
record encodings after genuinely acknowledged activation completion. The caller
must independently authenticate the original completion and fresh execution
authority. Persistence checks DATA association, not signatures or permission.
Missing local records never prove non-execution or authorize SQL retry.

## Fixed API and original association

The custody client and journal expose:

- `claim_oidc_session_activation_completion_recovery_consume_attempt`
- `append_oidc_session_activation_completion_recovery_consume_inputs`
- `append_oidc_session_activation_completion_recovery_consume_prepared`
- `append_oidc_session_activation_completion_recovery_consume_exported`

All take keyword-only `finalization_digest`, `activation_authorization_digest`,
`activation_completion_originals`, `reconciliation_digest`, `work`, `current`
and optional `maximum_original_bytes`. Appends also take `originals`: input
issuer raw2, prepare raw6 or export raw7, respectively. The claim returns the
existing consume slot digest; appends return the retained record digest.

`activation_completion_originals` is exact acknowledged activation raw4.
`reconciliation_digest=None` selects its original completion record; otherwise
the digest selects the separate immutable **activation-phase** reconciliation.
The reader requires the actual activation claim, prepared record, grant,
reservation and SQL-claimed association, then reads those bounded originals and
the selected completion or reconciliation claim/response. It does not read an
unsigned SQL-outcome body or infer execution from its presence or absence.

The retained prepared authorization's actual framed identity must equal
`activation_authorization_digest`. The selected raw4 must match byte-for-byte,
and a separate reconciliation must have the exact locator, caller and immutable
predecessor association. These are content/association checks only; genuine
same-call historical admission remains mandatory at the caller.

If original activation completion is absent, the existing consume prefix may
associate with that exact separate activation reconciliation claim/response.
Recovery checks fixed target, phase, source, authorization and predecessor
metadata; it does not synthesize completion or replace uncertainty. There is no
new codec or historical source-cohort exception. Existing normal consume methods
remain unchanged.

## Same irreversible target, one exact-work sequence

The claim uses the same `(finalization_digest, activation_authorization_digest)`
slot and global finalization target index as normal consume planning. An existing
consume claim from **any** path refuses, even under a fresh actor, changed caller
identity or process restart. The claim is published before input-issuer contact.
A lost or unusable reply cannot reopen acquisition.

Only this work's successful new guarded claim permits `inputs`, then `prepared`,
then `exported`, once each. The transient latch retains only the exact work,
reconciliation locator and next kind; it is never recovered and does not enable
the normal live-publication API. A skipped, repeated or reordered stage refuses.
Uncertain prepare DATA may be retained, but cannot authorize export. Export
publication ends this append sequence; it does not authorize further execution.

Framing-bounded raw replies are retained before the caller's status, signature
or matching interpretation. Prior consume stage bodies need not be reread for
each append: their admitted immutable metadata, source, fixed prefix and actual
file identities remain checked, along with the exact consume claim. No posted
request, old token, assertion, cookie or returned token is journaled.

## One allowance and native publication

`maximum_original_bytes` is an exact tightening integer from zero through 64 MiB;
`None` retains that ceiling. Before body one, the method reserves three times
the actual selected encoded originals, three times the new encoded publication
upper bound, and `consume.COMPLETION_RECOVERY_METADATA_BYTES` (16 KiB). The
publication bound is `consume._MAX_HEADER_BYTES + 8*len(originals) + sum(lengths)`.
Actual frame limits are checked before encoding. The caller separately reserves
its held graphs and future work; its 2 MiB custody lane can reject otherwise
valid large history without enlarging the original aggregate allowance.

The historical target and combined finalization loader reserve eight times the
actual cold-parent original length, measured from the startup owner's original
sealed memfd identity. Full startup continuity, the exact original descriptor
metadata and the existing current guard bracket that measurement. No body is
reread and no configuration graph or key object is traversed. This replaces only
the former eight-times-4-MiB maximum estimate: the 64 MiB aggregate, replay
headroom, cold planner/enrollment reservations and eight selected-history
representations are unchanged. The parent is counted once in each phase, so a
small admitted parent can coexist with the separately reserved 32 MiB future
lane; a large parent or history still refuses before the first history body.

Each method charges its original work directly before body reads and publication,
including bounded native metadata scans. Do not wrap it in a metrics-stable
callback or double-charge the same I/O. `current` retains original owner/actor
resource ancestry and must not recursively select records or reacquire the
journal lock.

Publication reuses the completion native transition guard: source-fixed names,
actual created inode, exact mode/size, rename, fsync, normal close and immutable
readback under the full original guard. No readiness bypass or descriptor
exemption is introduced. Missing required history, duplicate claim or insufficient
capacity refuses; corruption, changed immutable files or publication uncertainty
poison the owner. Uncertain claims are never removed or retried.

This source slice performs no public SQL, consume authorization/grant/reservation,
protected token release or current-session/cookie completion. Those require
their own actual source-owned continuation and independent authority. Byte/work
bounds are not heap/RSS measurements; local fsync is not an independent rollback
witness. Source only: unbuilt, unexecuted and unprovisioned.

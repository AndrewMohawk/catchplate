# Completion-only recovery originals and attempts

This source-only custody slice supports [earlier-stage public recovery](oidc-session-activation-public-recovery.md).
It is unbuilt and unexecuted. Storage admits framing and local immutable
associations, never completion, SQL execution, current-session state or a token.
The original activation/consume completion outcomes and hints are not overwritten.

## Fixed historical bundle

The actual custody client and journal expose
`load_oidc_session_activation_completion_recovery_controls(finalization_digest, *, phase, work, current, maximum_original_bytes=None)`.
`phase` is exactly `activation` or `consume`. The result is `None` when required
controls are absent, otherwise this ordinary tuple10 of existing records:

| Index | Activation | Consume |
| --- | --- | --- |
| 0 | Original activation dispatch claim | Same original activation dispatch claim |
| 1 | `None` | Consume claim |
| 2 | Prepared raw5: authorization, plan, ciphertext, expectations, before vector | Prepared raw6: status, typed request, scope, signed plan, plan digest, journal digest |
| 3 | `None` | Exported raw7: status, typed request, scope, signed plan, ciphertext, plan digest, journal digest |
| 4 | `None` | Authorized raw1 |
| 5 | Grant raw1 | Grant raw1 |
| 6 | Reserved raw3 | Reserved raw3 |
| 7 | Original completion raw4, or `None` | Original completion raw4, or `None` |
| 8 | `None` | Original unsigned completion hints raw2, or `None` |
| 9 | Original SQL-claimed raw0 record | Original SQL-claimed raw0 record |

The fixed admitted indexes choose these names. Required prepared, exported,
authorized, grant, reservation or SQL-claimed absence is unavailable, not
nonexecution or permission to retry. An absent original completion observation
does not by itself forbid a separately authorized first completion-only attempt.
There is no SQL-outcome read or full-prefix body load. Known prefix metadata and
immutable file identities are still checked. The genuine historical consumer,
not the loader, rejects uncertain preparation and authenticates each original.

Before the first selected body, three times the sum of actual immutable encoded
sizes plus 16 KiB metadata reserve must fit the caller's remaining representation
allowance. `None` uses the existing 64 MiB ceiling; an exact integer from zero
through that ceiling only tightens it. The caller separately reserves retained
actor/configuration material, future response/publication buffers and later
genuine admission. Work is charged directly on the same cumulative ledger;
native guarded reads use fixed allocations, exact EOF and normal close. A valid
oversized selection or preflight work exhaustion refuses before body allocation,
outside corruption poisoning. This is not a heap/RSS guarantee.

## One attempt, separate opaque response

The new `control_plane_oidc_session_activation_completion_recovery_records`
codec owns two files per separately counted logical claim. Its slot is framed
from **finalization locator and fixed phase only**. A fresh actor, changed config,
process restart or identical request cannot create a second attempt for that
slot. No previous LIVE activation or consume claim is renewed.

`claim_oidc_session_activation_completion_recovery_attempt` takes keyword-only
`finalization_digest`, `phase`, `authorization_digest`, `packet_digest`,
`recovery_configuration_digest`, `work`, `current` and optional
`maximum_original_bytes`. The orchestrator derives those pins from genuine
historical controls and the independently admitted exact completion configuration;
the journal does not authenticate caller-provided digests. It internally binds
the original completion-record digest, with an explicit absence encoding when
there was no original observation. The claim is durable before socket contact.
An existing or recovered claim refuses further contact even under a fresh actor.

`append_oidc_session_activation_completion_recovery_response` takes the same
keywords plus `originals`. Only this owner's successful new in-memory claim may
append once. The response is immutable **DATA before interpretation**:

- Activation raw4: status, completion-request digest, completion-request original,
  state-receipt original; caps 12, 71, 256 KiB and 16 KiB.
- Consume raw6: that same raw4 plus packet-digest hint and unsigned descriptor;
  extra caps 71 and 1024 bytes.

Every body may be empty or contain arbitrary bounded bytes at this storage
boundary. In particular, a returned uncertain response is retained separately;
neither its marker nor an acknowledged marker proves completion. Only subsequent
genuine original verification constitutes reconciliation. The codec retains no
request, token, cookie, assertion, successful permission or new SQL authority.

`load_oidc_session_activation_completion_recovery_records(finalization_digest, *, phase, work, current, maximum_original_bytes=None)`
returns `None` or `CompletionRecoveryRecords(claim, response_or_None)`. It reserves
three actual encoded footprints plus 16 KiB before reading. A safe maximum is
`3 * (MAX_CLAIM_BYTES + MAX_RESPONSE_BYTES[phase_index]) + METADATA_RESERVATION_BYTES`.
A fresh authorized consumer may independently re-admit an exact stored response
without another socket exchange. A claim without usable authenticated response
remains terminal unknown, never an automatic retry or local proof of no effect.

## Publication continuity and capacity

The codec exports `MAX_CLAIM_BYTES`, `MAX_CLAIM_IO_BYTES`, per-phase framed
`MAX_RESPONSE_BYTES`, `METADATA_RESERVATION_BYTES` and `_append_io_bytes`.
Claim preflight requires its fixed I/O reservation plus metadata; response
preflight requires the actual append-I/O reservation plus metadata, before
encoding/publication. The methods directly charge work; callers must not charge
the same I/O again or hide them inside a work-free callback. Logical-record and
byte quotas are unchanged, and the new family is counted in every existing
admission path. Its two files fit the existing base physical allowance; consume
suffix allowances do not widen.

The supplied guard is the original owner/resource ancestor and must not reenter
record selection or acquire another journal operation. Ordinary reads never scan
prefix bodies or directories. **Publication alone** uses a narrow metadata-only
inventory scan at its own create/rename/close or failed-temp-removal transitions:
the actual native-created descriptor pins the inode, and only its source-fixed
temporary/final name may differ from the known immutable inventory. Scans stream
without retaining all names and are precharged from the actual admitted file
count. Large metadata work may refuse before publication. The directory descriptor,
every existing immutable file and the expected own inode must still match before
the expected directory stamp advances and full original ancestry runs again.
Readiness is never disabled or bypassed.

The optional witness publication guards default to the unchanged old path.
The new path guards native writes, chmod, fsync, rename and close, then performs
guarded immutable readback. An expired guard cannot skip owned descriptor/temp
cleanup; visible publication is never undone. Failed transitions, unexpected
entries, inode replacement, close uncertainty or corrupted retained originals
poison the owner. Filesystem durability still depends on the provisioned
filesystem honoring fsync; this is not isolation from host root or an independent
rollback anchor. No resources are provisioned or runtime behavior verified here.

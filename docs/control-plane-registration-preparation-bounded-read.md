# Bounded retained registration preparation read

This is a source-only H05 prerequisite, not historical authority or completion
of H05. No build, test, runtime, provisioned resource or production acceptance is
claimed. [Historical authority resolution](historical-authority-resolution.md)
must still independently admit the original cohort; local records cannot choose
newer pins or authorize effects.

The actual client and journal expose:

```text
load_registration_preparation(execution_digest, *,
    maximum_original_bytes=None, work=None, current=None)
    -> (execution PreparedRecord, signer PreparedRecord)
```

Supplying none of the optional keywords preserves existing callers. The bounded
consumer supplies all three together and invokes the method directly: it charges
the original cumulative work itself, so a stable production callback must not
wrap it. `current` is the original upstream owner/lifetime guard; it must not
reenter a journal loader, acquire its I/O lock or publish records.

The bounded pair branch selects only the admitted execution-to-signer association and the
two exact prepared records. It uses their existing family, operation, source and
immutable file identities, not a filesystem/body scan. Both prepared entries
must be retention-only with no forwarding markers. The unchanged association
must bind the same execution and signer digests and their original source token.

Before the first body read, all three files' known metadata and actual encoded
sizes are checked. Required capacity is:

```text
3 * (association encoded bytes + execution encoded bytes + signer encoded bytes)
    + REGISTRATION_PREPARATION_METADATA_BYTES
```

The journal exports `REGISTRATION_PREPARATION_METADATA_BYTES = 16 KiB` and
`REGISTRATION_PREPARATION_MAX_BYTES = 64 MiB`. The supplied maximum can only
tighten this ceiling. The caller must subtract already-held independent root/
historical material and future capture/replay reservations before calling; this
is not another expanded allowance or a Python heap/RSS guarantee. The full body
I/O/decoding charge precedes body one under that same cumulative work.

Actual reads reuse the finalization combined-history reader: guards surround
native open/stat/read/exact EOF and normal close, admitted inode/ownership/mode/
size are rechecked, and the same immutable metadata is checked after decoding.
Known missing association and insufficient capacity refuse before bodies without
poisoning unchanged data. Changed files, malformed bodies, association mismatch
or guarded I/O/cleanup failure poison the journal; there is no retry or repair.

Returned records are ordinary original DATA. Their exact stored source labels
and signed bytes are never replaced with current labels. Neither successful
readback nor matching source metadata establishes a root signature, enrollment,
historical configuration, permission, delivery, SQL outcome or present session.
The real recovery consumer still performs independent cohort resolution and
genuine original admission on the returned pair under the same work/window.

## Combined history for actual recovery

The source-fixed recovery consumer uses a distinct required-keyword entry point:

```text
load_registration_recovery_history(execution_digest, *,
    maximum_original_bytes, work, current)
    -> ((execution PreparedRecord, signer PreparedRecord), RegistrationOutcomes)
```

It extends that same fixed inventory with every present existing reservation,
SQL claim, SQL outcome, completion outcome and separate completion reconciliation.
The returned `RegistrationOutcomes` exposes `source_revision`, `local_digest`,
`reservation`, `sql_attempt`, `sql_outcome`, `completion_outcome` and
`completion_reconciled`; absent outcome records remain `None`. No absence is
translated into nonexecution, retry, new checkpoint or authority.

All three to eight selected files share **one** preflight before body one:
`3 * sum(actual encoded selected bytes) + 16 KiB`, within the caller's remaining
64 MiB allowance. There is no separate outcomes allowance or later unbounded
pair/outcome reload. Existing prerequisite/source metadata checks are repeated;
each decoded outcome must match its actual retained kind, preparation digest,
source token and content digest. A reconciliation still requires the immutable
original uncertain completion outcome. This read changes or appends nothing.
The original pair API, its bounded mode and legacy unmetered callers retain
their previous return shape and behavior.

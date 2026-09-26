# Persisted initial body-observer custody

Status: source-only, unbuilt and unexecuted. This path persists actual **initial**
observations while their target remains gated. It is not continuous history,
readiness, workload resume, signed evidence or production storage admission.

`HeldInitialBodyHistoryV14::persist_initial(directory: OwnedFd)` consumes the
actual initial owner and a preprovisioned directory descriptor, returning a
[BodyObservationSessionV14](../data-plane/decision-gate-rs/src/body_observer_session_v14.rs).
There is no caller-record, parsed-marker or successful-proof constructor.

## Four-stage publication

1. **Retain actual custody.** Move the initial owner first and verify its real
   stopped/gated target and original history under the existing deadline.
2. **Adopt protected storage.** Consume the supplied directory, reopen `.` to
   obtain an independent open file description, take a nonblocking exclusive
   advisory lock, and require an empty source-checked directory.
3. **Publish exact originals.** Exclusively create `stop.json`, then all eight
   task originals in the fixed order below, then `maps.bin`, `snapshot.json`
   and `event.json`; publish `initial.commit` last. Each file completes the
   file/readback/directory-sync boundary before the next one.
4. **Return the gated session.** Join retained store contents/head/counts to the
   same actual initial owner and recheck gated custody. No Ready or continuation
   message follows from success.

The [store](../data-plane/decision-gate-rs/src/body_observer_history_store_v14.rs)
owns all thirteen retained originals. The session retains the initial owner **before**
the store in field-drop order, so fail-closed worker cleanup precedes release of
the retained store. `verify_gated(deadline)` can only shorten the original bound;
a failure permanently poisons that session. `abort` remains available, without
a new cleanup window. `stored_bytes` and `history_head_sha256` are inspection
values, not fresh verification or permission.

## Files and commit marker

| Fixed file | Original content | Source maximum |
| --- | --- | --- |
| `stop.json` | Exact typed-canonical worker stop original | 4 KiB |
| `target-before-status.bin` | Original target status, before task acquisition | 64 KiB |
| `target-before-stat.bin` | Original target stat, before task acquisition | 16 KiB |
| `target-after-status.bin` | Original target status, after task acquisition | 64 KiB |
| `target-after-stat.bin` | Original target stat, after task acquisition | 16 KiB |
| `worker-before-status.bin` | Original worker status, before task acquisition | 64 KiB |
| `worker-before-stat.bin` | Original worker stat, before task acquisition | 16 KiB |
| `worker-after-status.bin` | Original worker status, after task acquisition | 64 KiB |
| `worker-after-stat.bin` | Original worker stat, after task acquisition | 16 KiB |
| `maps.bin` | Exact original procfs maps bytes | 4 MiB |
| `snapshot.json` | Complete typed-canonical initial mapping snapshot | 16 MiB |
| `event.json` | Typed-canonical sequence-1 `Initial` event | 256 KiB |
| `initial.commit` | Fixed binary scope/length/digest binding | 640 bytes |

The eight status/stat originals have a separate combined cap of 327,680 bytes;
the stop original is charged separately. They are obtained only from the actual
initial owner's retained, authenticated worker handoff, not from file paths or
caller-provided records. The fixed
[task-original collection](../data-plane/decision-gate-rs/src/body_observer_task_originals_v14.rs)
preserves those bytes and their identities.

`stored_bytes` counts the actual bytes in all thirteen files, not disk allocation,
filesystem metadata or a provisioned quota. Stop, task and map digests are raw SHA-256;
snapshot/event identities use their distinct
[history domains](controller-body-observer-history.md#closed-originals-and-bounds).
All original bytes remain stored; a digest cannot replace a missing file.

The marker starts with the exact NUL-terminated bytes
`serverware.controllerBodyInitialHistoryCommit/v15`, followed by this fixed
584-byte payload in order:

- Context digest, 32 bytes.
- Target pidfd inode, target PID-namespace inode and original scope deadline,
  each unsigned 64-bit big-endian.
- Admitted maximum live tasks, unsigned 32-bit big-endian.
- Event count, unsigned 64-bit big-endian, exactly one.
- Maps, snapshot and event respectively: original length as unsigned 64-bit
  big-endian, then the applicable 32-byte digest.
- Task-original binding digest, 32 bytes; task-original count as unsigned
  32-bit big-endian, exactly eight.
- Each task original in the table's fixed order: original length as unsigned
  64-bit big-endian, then raw SHA-256, 32 bytes.
- Stop-original length as unsigned 64-bit big-endian, then its raw SHA-256,
  32 bytes.

The task binding commits the fixed NUL-terminated domain
`serverware/controller-body-task-originals/v14`, the stop-original length
(u64BE) and exact stop bytes, then each task index (u32BE), length (u64BE) and
exact original bytes. Retaining `stop.json` preserves that binding's preimage,
rather than retaining only its digest.

This local v15 marker is explicitly incompatible with the earlier four-file
v14 marker; there is no parser, migration, fallback or old-marker adoption.
Existing signed evidence v13 and unsigned history v14 formats are unchanged.

The source produces this marker from actual retained custody; it does not parse
one as an authorization or recovery input. Its presence alone is not a complete
publication assertion: successful return also requires the exact original joins,
sync boundaries and final custody checks. It is neither a signature nor a latest-
checkpoint/anti-rollback authority.

## Filesystem and failure contract

The [file owner](../data-plane/decision-gate-rs/src/body_observer_history_files_v14.rs)
requires a preexisting empty root `0:0` directory with exact mode `0700`. Its
structural filesystem filter accepts ext-family magic `0xef53` or XFS magic
`0x58465342`. The ext magic does **not** distinguish ext2/ext3/ext4 or establish
journaling. No directory, mount, key or storage domain is provisioned here.

Files are no-follow, exclusive creations: regular, root-owned, single-link,
initially `0600`, then `0400` after writing. The owner syncs the file, closes its
writer, reopens and compares the exact original, syncs the directory, and retains
the reader. Verification checks held and named identities/metadata and their
directory/filesystem joins. Read-only mode is not an FS_IMMUTABLE claim.

The separate directory sync matters because syncing file contents does not by
itself persist the containing directory entry. The operation can block until
the storage device reports completion. Before/after deadline checks and
`O_NONBLOCK` do not interrupt a blocked regular-file write or sync; an admitted
outer watchdog remains necessary. See [fsync(2)](https://man7.org/linux/man-pages/man2/fsync.2.html).

The fresh open file description prevents the caller's duplicated descriptor
from sharing the owner's lock. This is still an advisory cooperative lock;
root DAC and flock do not isolate storage from hostile root or another writer
that can bypass those protections. See [flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html).

Publication or verification failure poisons its owner. Partial files remain in
place, and a later fresh attempt does not adopt that nonempty directory. There
is no overwrite, deletion, retry, automatic repair, reset or recovery API.
Closing/aborting the owner does not erase the originals or certify destruction.

Independent admission must still establish workload-inaccessible storage,
filesystem/device behavior, quotas, preprovisioned parent-entry durability,
watchdog ownership and any required power-loss/rollback protection. A successful
local sync call is not a universal guarantee of those properties. The controller
output tmpfs is not substituted for this storage domain.

## Remaining integrated lifecycle

This is the persisted initial gated session only. It supplies no continuous
event transport/append loop, scheduler, actual MM-sharing or mapping policy,
host-surviving final-status source, independent output reconciliation, signer
or serving lifecycle. Native wait-status/syscall-info originals and ongoing
events are not archived by these thirteen files: this is not a complete
acquisition archive. Existing v13 admission remains unchanged. The
[lifecycle design](controller-body-observer-lifecycle-design.md) defines those
cohesive dependencies and the future acknowledgment-before-continuation rule;
this initial store does not activate that transition. Frozen preparation and
full verification remain outstanding; no runtime or failure test ran here.

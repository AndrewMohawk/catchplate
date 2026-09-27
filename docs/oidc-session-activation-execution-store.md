# Activation execution-bundle store

[`ActivationExecutionBundleStore`](../serverware/authority_oidc_session_activation_execution_store.py)
retains the first exact encrypted execution bundle in a separate, independently
provisioned private directory. This is source-only implementation: unbuilt,
unexecuted and unprovisioned. Storage integrity is not plan authentication,
currentness, permission, protected SQL execution or session activation.

## Independent owner and record

The constructor requires the existing directory descriptor and its exact device,
inode, UID and GID; record/byte quotas; configuration digest; an independent
32-byte bundle key; and the caller's original work/window and optional inherited
transport bound. Source revision is fixed by the implementation. The current
process must match the pinned UID/GID and remains PID-bound. It opens `.` as an
independent descriptor, takes a nonblocking exclusive flock and requires mode
0700. No directory or key is created. The caller must ensure this is separate
from the original journal and that the bundle key is independently admitted and
distinct from delivery/journal keys; this store holds only the bundle key.

The private configuration snapshot is exactly
`(source, configuration_digest, bundle_key, (device, inode, uid, gid), maximum_records, quota_bytes)`.
It is an internal continuity input, not a successful authority carrier.

Each `SWOAS001` record contains a 24-byte header: magic, big-endian unsigned
context length (4 bytes), original-plan length (4 bytes), and bundle length
(8 bytes). The bodies are exactly canonical context JSON, the original canonical
signed-plan envelope, and the encrypted bundle. Context is the bundle codec's
closed seven-field context, including configuration/request/plan/journal digests.
No plaintext token, plaintext journal document or key is persisted in this record.

The whole record is bounded to 64 MiB, including all framing and bodies. Context
is at most 4096 bytes; plan bytes use the actual plan-contract cap. The supplied
cumulative work allowance and existing packet caps are not enlarged. Records
are limited to at most 1024 and the configured quota to at most 8 GiB; lower
provisioned limits apply before publication.

The stable basename is `execution-` followed by the hex part of the framed
canonical-context digest under
`serverware.oidcSessionActivationExecutionStoreSlot/v1`. There is no supplied
path, latest-record lookup or heuristic association.

## First bytes, recovery and uncertainty

`read(*, context, envelope_bytes, live_window, work, transport_deadline_ns)`
returns the exact retained ciphertext bundle or `None`, after joining the
supplied original plan to the closed context even for an absent slot. Absence
is only local absence, not permission or evidence that no external effect
occurred. Both read and append require the original inherited deadline.

`append(*, context, envelope_bytes, bundle_bytes, live_window, work, transport_deadline_ns)`
publishes and returns the first exact bundle. An exact repeat is idempotent;
different ciphertext conflicts even if it encrypts identical plaintext. The
owning caller must read before creating a randomized candidate when it intends
to recover the first bytes. The store never regenerates or overwrites a bundle.

Constructor recovery, reads and publication readback validate canonical context,
source/configuration joins, original plan identity and request digest. They
genuinely open the [execution bundle](oidc-session-activation-execution-bundle.md)
under its independently supplied key and expected context, validate the exact
canonical journal-v2 document, and join its embedded plan bytes to the stored
envelope. Decrypted originals remain private transient data, never the public
return value. These checks do not verify planner signatures or replay the plan.
Expired plan originals may remain stored: the current storage processing window
only bounds this operation and does not refresh or backdate original authority.

The actual witness I/O helper writes owner-only records, changes mode to 0400,
fsyncs, and publishes with no-replace rename followed by directory fsync. Recovery
fsyncs each validated record and the directory. Bounded inventory, no-follow
opens, single-link regular files, exact owner/device, stable before/after and
named identities, first-record hashes, directory stamps and lock continuity
guard subsequent access. Unknown entries, including orphan temporary files,
fail closed; the store does not prune them.

Any uncertain publication or locked-operation failure poisons the owner. A
visible record is never removed. A fresh owner requires complete validated
recovery; failure is not authorization to repeat transport or SQL. Closing owns
only its independent descriptor and claims neither deletion nor key erasure.
These trusted-host-local checks are not malicious-root protection, an off-host
anti-rollback anchor or independently current state.

The [plan owner](oidc-session-activation-plan-owner.md) and genuine receiving
replay remain responsible for original signatures, live authority and exact
independent configuration. Durable storage alone does not supply execution
authorization, reservation, one-use dispatch, completion or token release.

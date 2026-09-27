# First-exact consume execution ciphertext

[`DeliveryExecutionBundleStore`](../serverware/authority_oidc_session_activation_delivery_execution_store.py)
retains the first exact encrypted consume-original bundle under independently
supplied configuration, key and directory pins. This is source-only, unbuilt and
unexecuted. Storage integrity is not caller permission, full semantic replay,
protected execution, completion, currentness or plaintext-release authority.

## Fixed owner and format

The constructor matches the activation store's explicit keyword-only interface:
`directory_fd`, `expected_device`, `expected_inode`, `expected_uid`,
`expected_gid`, `maximum_records`, `quota_bytes`, `configuration_digest`,
`bundle_key`, `live_window`, `work`, and optional `transport_deadline_ns`.
It creates no directory or key. The PID and effective UID/GID must match the
pinned owner. The existing directory must be mode `0700` with the exact
device/inode/owner; opening `.` takes a separate nonblocking exclusive flock
lease rather than sharing the caller descriptor's lease.

The private `_snapshot_configuration()` returns the same held six-tuple:
`(sourceRevision, configurationDigest, bundleKey, (device, inode, uid, gid), maximumRecords, quotaBytes)`.
It performs PID/identity/readiness checks, not an unmetered recovery scan or
authority admission. Both supplied key bytes and configuration remain private.
The composing owner must independently admit the exact raw32 key, separate it
from the consume journal and historical bundle/delivery keys, and require a
different directory from the original journal.

The distinct format is `SWODS001`. Its 24-byte header contains the eight-byte
magic, big-endian context length (four bytes), original-plan length (four bytes)
and ciphertext-bundle length (eight bytes). The bodies are canonical context,
the exact original consume-plan envelope and the original encrypted bundle.
The basename is `consume-execution-` plus the hex portion of the framed context
digest under `serverware.oidcSessionActivationDeliveryExecutionStoreSlot/v1`.
There is no supplied pathname, latest-record lookup or alternate format.

The whole record, including all framing, is at most **64 MiB**. Context is at
most 4096 bytes and the plan uses its actual 16 KiB contract cap. Record count is
bounded to 1–1024 and quota to 1 byte–8 GiB; the independently configured lower
limits apply. These bounds do not enlarge the caller's cumulative work or
transport budget. `HEADER_BYTES`, `MAX_RECORD_BYTES` and
`_context_bytes(context, work)` expose the actual framing bounds for the private
exporter's complete-record size check.

## Durable first bytes, never regeneration

`read(*, context, envelope_bytes, live_window, work, transport_deadline_ns)`
returns retained ciphertext or local absence (`None`). Even an absent lookup
joins the supplied original plan to the expected configuration/request/plan
context. Absence is not proof that no remote action happened or permission to
retry. `append` accepts the same keywords plus `bundle_bytes` and returns the
first exact ciphertext. An identical repeat is idempotent; changed ciphertext
conflicts even if it encrypts equal plaintext. Recovery must read before any
new randomized sealing; the store never reseals, overwrites or clears a record.

Every recovered/read/published record genuinely opens the distinct
[consume bundle](oidc-session-activation-delivery-execution-bundle.md), validates
the canonical [sixteen-field original document](oidc-session-activation-delivery-journal.md),
and compares its embedded plan bytes to the stored envelope. Activation bundle,
journal or plan formats are not fallbacks. Decrypted originals are transient
private data and never the return value. These checks are not plan-signature or
semantic replay; the caller must independently perform genuine original replay.

The actual `WitnessJournalIO` path preserves owner-only writes, mode `0400`,
file fsync, no-replace publication and directory fsync. Constructor recovery
fsyncs each validated record and the directory under the supplied original
work/window. Reads check no-follow single-link regular files, exact owner/device,
stable descriptor/path identities, whole-record hashes and directory/inventory
continuity. Unknown entries and orphan temporary files fail closed, without
pruning. Read/append require a positive inherited deadline; no clock is reopened.

Uncertain publication or failure inside a locked operation poisons the owner.
Visible originals survive; a fresh owner must recover and validate the complete
bounded inventory. `close()` releases only its own descriptor, not records, and
claims no key erasure. Current storage liveness does not renew an expired plan
or create historical execution authority.

## Shared mechanics, separate authority

The private [storage engine](../serverware/authority_oidc_execution_store_core.py)
accepts exactly the actual activation and consume wrapper classes. Each public
wrapper also rejects the other receiver type and subclasses. No caller chooses
a profile, codec, callback or success carrier. The activation wrapper preserves
its original `SWOAS001`, `execution-` prefix, slot domain, codec, API and bounds;
only the filesystem/lifetime mechanics are shared.

This is a trusted-host-local custody boundary, not malicious-root protection,
an off-host rollback witness or atomic action-time authority. The store itself
does not authenticate a public action, issue a grant, reserve/execute SQL,
reconcile completion or release plaintext. Independent cold key/resource
admission, receiving full replay and the protected consume pipeline retain
their own requirements; no provisioning or production gate is claimed here.

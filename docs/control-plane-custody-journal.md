# Opaque caller custody journal

Source-only caller storage implementation; unbuilt and unexecuted. This is
separate from the authority's signed custody and replay protocols and does not
advance their source revision.

`control_plane_custody_records.py` encodes exact original bytes without admitting
their signatures, history, keys or policy:

- Evidence raw-six: intent, relay, envelope, inputs, evaluation context and
  independent historical expectations.
- Transition raw-seven: intent, relay, envelope, proof, inputs, context and
  independent historical expectations.

The fixed prepared-record frame commits the family, purpose/operation selector,
source token, lengths and every original byte. Its SHA-256 identity uses
`serverware.controlPlaneCustodyPreparedRecord/v1`. Originals are bounded to
64 MiB in aggregate, with each of the first two controls at most 4 MiB; an
encoded record is at most 64 MiB + 323 bytes. Decoding an old
source token preserves bytes, not compatibility or replay authority.

## Local state boundary

The journal requires an explicitly preprovisioned private directory descriptor,
its independently supplied identity, an exclusive lease and finite storage
quotas. It does not choose or create an ambient storage location.

`CustodyJournal` takes `directory_fd`, expected device/inode/UID/GID,
`quota_bytes` and `maximum_records`. It opens its own directory handle, holds a
nonblocking exclusive lease and binds the owner to the opening process. The
directory must have mode 0700; record files must have mode 0400, one link and
the pinned ownership. Source ceilings are 8 GiB and 4096 prepared records
(at most 8192 physical files). Each prepared record reserves space for its
fixed 40-byte attempt marker.

```text
exact originals -> immutable PREPARED record
                -> irreversible local ATTEMPTED marker
                -> future explicit forwarding, not implemented here
```

The intended caller must establish ATTEMPTED before beginning any network
forward. `append_evidence` and `append_transition` retain PREPARED originals;
`load` returns the original prepared record, `inventory` returns bounded local
metadata, and `claim_attempt` establishes the one-attempt barrier. Constructor
recovery is mandatory. Unknown or temporary files poison admission rather than
being silently repaired; published files are not deleted by the library.
`close` or the context manager releases the owned handle and lease.
Close before forking: child calls are rejected, but an inherited descriptor can
keep the parent's lease alive until the child closes it or exits. Failed
publication may remove its own unpublished temporary file; recovery performs
no cleanup and never deletes a published record.

An ATTEMPTED marker means only that an attempt may have occurred: it is not a
signed remote receipt, execution result or proof of commit. Local errors and
crashes cannot establish that a remote operation was absent or rolled back.
There is no automatic retry, regeneration or reconciliation authority. A local
journal also cannot prove resistance to an administrator restoring older storage.
The one-attempt rule is per exact local record, not logical-operation
deduplication across new controls or source revisions.

## Integration still required

An authoritative caller process, its directory/lease/quota provisioning and an
authenticated caller-to-verifier handoff remain missing. No current forwarding
path is protected by this library. The authority's verifier mutable-state policy,
SQL privileges and business-execution gates are unchanged.

The [historical resolver](authority-historical-replay.md) supplies a separate
trust-admission boundary; these opaque stored bytes cannot replace it. Explicit
caller recovery, independent provisioning and frozen build/runtime verification
remain required.

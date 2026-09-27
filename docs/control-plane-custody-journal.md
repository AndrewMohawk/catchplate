# Opaque caller custody journal

Caller storage, private forwarding and explicit read-only reconciliation;
unbuilt and unexecuted. Local storage remains separate
from signed custody/replay authority.

`control_plane_custody_records.py` encodes exact original bytes without admitting
their signatures, history, keys or policy:

- Evidence raw-six: intent, relay, envelope, inputs, evaluation context and
  independent historical expectations.
- Transition raw-seven: intent, relay, envelope, proof, inputs, context and
  independent historical expectations.

The legacy `SWCPR001` prepared-record frame commits the family, purpose/operation selector,
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
the pinned ownership. Source ceilings remain 8 GiB and 4096 prepared records
(at most 12288 physical files). Each legacy prepared record reserves its fixed 40-byte
attempt marker and the maximum 370-byte observation frame while those markers
are missing. Existing prepared/attempted journals recover without rewriting
their originals, but must have enough configured quota for the missing
observation reservation. Insufficient quota fails admission; it does not cause
cleanup, automatic quota expansion or removal of an attempt barrier.

The separate registration execution-grant profile counts toward the same byte
and record quotas, but reserves no attempt or observation space: it has no
delivery contract. The following lifecycle applies only to the five legacy
evidence/transition profiles.

```text
exact originals -> immutable PREPARED record
                -> irreversible local ATTEMPTED marker
                -> one explicit caller-to-relay-to-verifier exchange
                -> explicit fresh readback -> immutable local OBSERVED metadata
```

The caller establishes ATTEMPTED before beginning any network forward.
`append_evidence` and `append_transition` retain PREPARED originals;
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

## Registration execution-grant retention

The independent
[`control_plane_registration_execution_records.py`](../serverware/control_plane_registration_execution_records.py)
codec preserves ten originals: caller authorization, planning request3,
planning response4, complete before-vector and signed grant. Its fixed family
is `registration-execution`, with selector
`webauthn.registration.evidence.admit`. The frame is `SWCPG001`, a two-byte
source-token length, the original ASCII source token, ten big-endian eight-byte
lengths and the exact bodies. Per-object and planning-group limits also apply;
the complete bodies are bounded to 64 MiB and the header to 346 bytes.
The local content identity uses the separate
`serverware.controlPlaneRegistrationExecutionGrantRecord/v1` domain. The old
`SWCPR001` bytes, hashes and five profiles are unchanged.

`CustodyJournal.append_registration_execution_grant(originals)` returns only
the local digest. It uses the existing private immutable-file publication:
exact writes, mode 0400, file fsync, no-replace publication, directory fsync
and exact readback. An exact duplicate rechecks the existing original instead
of replacing it. Publication failures poison the owner; a published file is
not removed or treated as proof that the operation failed before storage.
These guarantees depend on the provisioned filesystem honoring fsync, not a
hard syscall deadline or an independent anti-rollback witness.

Recovery and `load` dispatch only the two fixed formats and preserve the
record's original source revision. They reject attempt or observation markers
on a grant record; `claim_attempt` and `record_observation` also reject this
family. The client rejects it before forwarding or reconciliation. Inventory
and the existing admin recovery workspace expose retention-only metadata, not
raw originals or an execution action.

The private [prepare-and-retain composition](control-plane-registration-execution.md#explicit-local-retention)
performs genuine admission before storage. The lower-level codec and journal
do not authenticate the bytes. `load_registration_execution_grant` returns an
opaque `PreparedRecord`, retaining source, family, selector, digest and all ten
originals for future genuine replay; loading does not renew signed lifetimes
or establish current keys, roots, policy or permission. Older readers reject
the new magic and fail closed rather than downgrade, migrate or clean it up.
Old-source originals remain readable by this codec, not automatically replayable
or authoritative under the current source.

## Private configured forwarding

`ControlPlaneCustodyClient.from_environment` first uses the actual runtime-trust
loader: root signature, process/UID/GID, current source/configuration, attestation
and exact inherited-descriptor admission remain mandatory. Only afterward does
it open the journal's private directory handle. The borrowed journal descriptor
must already be in the root-admitted control-plane descriptor inventory; no
extra descriptor is silently allowed. Directory identity and quotas are explicit
provisioning inputs, not derived from a retrieved plan or a default path.
The original admitted runtime-attestation interval is retained without renewal.
Client and relay forwarding require it to remain live and cap their monotonic
deadline by its remaining lifetime, including final response checks. Expiry
after the durable attempt marker remains an uncertain, spent attempt.

Preparation and delivery remain separate. `forward_once(localdigest)` loads
the retained original record, refuses an unsupported source, establishes its
deadline, durably claims ATTEMPTED, and makes one fixed relay request. A failure
after the claim never clears it, even if no request bytes were sent. The client
does not create an intent, obtain a relay signature or infer retry permission.

The explicit `append_and_forward_evidence` and `append_and_forward_transition`
compositions complete the actual durable append before calling this unchanged
one-attempt path. Success returns the local digest with an unsigned peer
observation. An ordinary post-append failure retains that exact local digest in
`CustodyForwardOutcomeError`; cancellation propagates and the existing inventory
remains the recovery path. Neither repeated calls nor errors clear ATTEMPTED.
The admin [recovery API and portal workspace](control-plane-custody-recovery.md)
provide metadata inspection and explicit readback, not forwarding or retry.

```text
caller journal -> root-pinned runtime relay -> measured verifier
                                                |
                                      existing planner -> writer
```

The distinct five-selector binary protocol carries the unchanged raw-six or
raw-seven originals plus the current configuration digest. The runtime relay
and verifier compare that scope with their independently admitted configuration.
The existing control-plane/relay/verifier/planner/writer peer topology is
unchanged. The verifier authenticates the actual intent and relay and replays
the plan through the existing configured forwarding method; opaque journal
records and local markers do not substitute for that work.

Each transport exchange has bounded framing, peer checks, half-close and exact
EOF. The runtime relay starts its ingress deadline before queuing and preserves
that deadline across its verifier exchange and response. Verifier ingress has
its own bounded deadline; original signed-control windows continue to govern
downstream forwarding and persistence. This is not distributed cancellation:
a late/missing response can follow a commit. Detached failures close the
connection instead of falling through to a legacy JSON response or retry.

The returned digest/time is still an unsigned peer observation, not a remote
durability receipt or business-execution result. The authority's verifier
mutable-state policy, SQL privileges, legacy public operation gates and work
ceilings are unchanged.

## Explicit read-only reconciliation

`reconcile(localdigest)` requires an existing ATTEMPTED entry and rechecks its
exact originals and attempt marker on disk. It makes one explicit lookup request
through the same root-pinned runtime relay and measured verifier, under a new
bounded transport deadline and the caller's original live runtime attestation.
It does not call the retention forwarding path, claim another attempt, clear
the original marker or automatically repeat any exchange.

```text
ATTEMPTED originals -> authenticate original intent and relay
                   -> replay against admitted historical configuration
                   -> sign a fresh lookup-only request
                   -> read retained originals -> exact original-byte comparison
```

Original retention controls may have expired. Their configuration, generation
and issue time are used only to locate a verifier key in the archive already
admitted by the current root. They cannot introduce a new key. The verifier
authenticates the original intent and every body commitment before decoding
history, then resolves the actual historical planner receipt and evaluation
time. It authenticates the original relay, joins both complete control intervals
to that actual archived configuration, and replays the original plan against its
original policy and lifetime constraints.

Only after those checks does the verifier issue a fresh current-configuration
lookup control through the existing planner/writer read path. The current
archive and lookup authorization must remain live; none of this renews the old
plan, controls or business-execution authority. Returned raw-three evidence or
raw-four transition bodies must exactly match the stored originals. The verifier
also joins their retained-record identity through the existing read replay.

The result remains an unsigned peer observation with a retention timestamp,
not a signed durability receipt. Missing rows, timeouts and invalid replies are
errors, not proof of absence or permission to resend. Reconciliation currently
supports only the exact current source contract; old-source records remain
loadable but need a separately implemented versioned historical replay path.
No terminal business state or renewed delivery permission is created.

## First successful readback observation

After the genuine fresh lookup and exact original-byte comparison succeed,
`reconcile` durably records the first local unsigned observation. It never
records a missing row, timeout or failed response as a successful observation.
The immutable `observed-<local digest hex>` file contains:

```text
SWCPO001 (8 bytes)
local prepared digest (32) + retained-record digest (32)
retained-at epoch nanoseconds (8, positive signed-64-bit range)
current configuration digest (32)
source-token length (2) + ASCII source token (1..256)
```

The maximum frame is 370 bytes. It duplicates no plan bodies: the prepared
record still owns the exact raw-six/raw-seven originals. Configuration and
source identify the first observation's provenance, not the historical plan's
key admission or cross-source replay compatibility. The retained timestamp is
the returned first-retention time, not a new observation-time claim.

`CustodyJournal.record_observation` requires an existing prepared and attempted
record. An exact encoded repeat returns the first observation; any differing
metadata fails closed and never overwrites that file. Recovery rejects orphan,
malformed and oversized observations. `load_observation` rechecks the prepared
content hash, attempt marker, observation frame/local identity and pinned file
identities. A missing local observation returns `None` for an existing prepared
record; it says nothing about remote absence or whether a prior read succeeded.
Inventory adds an `observed` boolean without loading all original records.

The client exposes `inventory()` and `observation(localdigest)` for local
inspection. Repeated `reconcile` calls still perform a fresh successful lookup
and exact-original comparison before inspecting any prior observation. If the
new retained-record digest and time match, the client preserves the first
observation's configuration/source metadata unchanged. Different record/time
metadata fails closed. A stored observation never substitutes for fresh replay,
clears ATTEMPTED or authorizes another write, resend or automatic retry.

## Cold startup integration

Source `.119` connects the cold control-plane runner to the explicitly
provisioned journal descriptor handoff and one actual shared client/journal
owner. Startup admission and mandatory recovery precede its use; this is not a
new mutable-state grant to the measured verifier or a public HTTP route. See
the [startup contract](control-plane-custody-startup.md) for descriptor ownership
and lifecycle. This is source integration, not evidence that a deployment has
provisioned or exercised it.

## Integration still required

Deployment provisioning of the caller directory and signed descriptor inventory,
public invocation/preparation, complete orchestration, versioned cross-source
replay and business successor execution remain unfinished. Durable local
observations and cold-runner source integration do not close those boundaries.
This source path has not been built, launched or exercised.

The [historical resolver](authority-historical-replay.md) supplies a separate
trust-admission boundary; these opaque stored bytes cannot replace it. Explicit
deployment integration, independent provisioning and frozen build/runtime
verification remain required.

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
the pinned ownership. Source ceilings remain 8 GiB and 4096 prepared records;
the bounded recovery scan allows at most `7 * maximum_records` physical files.
The ceiling remains sufficient without expansion: each legacy record has at
most three files, evidence grant seven, signer record one, and finalization
grant five including its association, reservation, SQL claim and outcome slots.
Shared references do not duplicate those files.
Each legacy prepared record reserves its fixed 40-byte
attempt marker and the maximum 370-byte observation frame while those markers
are missing. Existing prepared/attempted journals recover without rewriting
their originals, but must have enough configured quota for the missing
observation reservation. Insufficient quota fails admission; it does not cause
cleanup, automatic quota expansion or removal of an attempt barrier.

The separate registration execution-grant, finalization-grant and signer-exchange profiles count
toward the same byte and record quotas, but reserve no attempt or observation
space: they have no legacy delivery contract. Their completed preparation uses
a separate bounded association marker, described below. The following lifecycle
applies only to the five legacy evidence/transition profiles.

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

Prepared-record recovery and `load` dispatch only the fixed `SWCPR001`,
`SWCPG001`, signer-exchange `SWCPS001` and finalization-grant `SWCPF001` formats and preserve each original
source revision.
They reject attempt or observation markers on all three retention-only registration families;
`claim_attempt` and `record_observation` also reject those families. The client
rejects them before forwarding or reconciliation. Inventory
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

## Associated registration preparation

The [signer-exchange profile](control-plane-registration-execution.md#standalone-signer-exchange-retention)
retains a different raw10 inventory: exact signer request8/response2, not caller
authorization/planning/vector/grant. Its source-specific local ID uses
`serverware.controlPlaneRegistrationSignerExchangeRecord/v1`; a grant record
cannot be reinterpreted as this signer record.

Genuine prepare-and-retain preserves both inventories from the same call.
`CustodyJournal.append_registration_preparation(execution_originals, *, signer_originals)`
and the same private cold-client API preflight every missing record and the
marker against the configured byte/record capacity, preserving legacy marker
reserves, before publication:

```text
1. publish exact signer record
   -> 2. publish exact grant record
      -> 3. publish associated-<grant digest hex> marker binding both local IDs
         -> preparation returns the existing grant ID (HTTP 202 localDigest)
```

The [association codec](../serverware/control_plane_registration_associations.py)
uses `SWCPL001`, a two-byte source length, the original ASCII source token, then
the grant and signer SHA-256 digests as two raw 32-byte fields and exact EOF.
The marker is at most 330 bytes. The filename uses the grant digest's hex only.
This design preserves the existing grant ID and both original frame formats,
without copying both inventories into a new combined payload. The trade-off is
durable partial originals if publication is interrupted, never automatic cleanup
or retry.
An exact existing association is rechecked idempotently; remapping it to another
signer is rejected. This does not authorize replaying the preparation/signing
workflow after an uncertain outcome.

Each original is independently immutable and durable. The last small marker
commits the local association; an original record alone is not complete
preparation. This is not a multi-file rollback transaction. An uncertain failure
may leave orphan originals or may follow marker publication. The owner never
infers absence or automatically retries preparation, signs again, deletes
published originals or renews a grant.

The private `load_registration_preparation(grantID)` rereads the actual marker
and both original records before returning `(grant PreparedRecord, signer
PreparedRecord)`. Absent/conflicting markers or cross-family/source references
fail closed. Recovery rejects dangling or inconsistent association markers;
unassociated originals remain individually loadable history, not completed
preparation. Reading the association does not authenticate signatures, replay
the original ceremony, prove current roots or permission, or establish the
evidence business row was committed. Later finalization still needs all those
separate gates. No new public original-export, forward, reconcile or attempt
action or public association-complete flag is added; in-memory preparation
remains raw10-only with no storage.

## Associated finalization-grant preparation

The separate [public grant preparation](public-registration-finalization-grant.md)
authenticates the dedicated finalization purpose before obtaining a new plan,
complete before-vector and genuine grant. It then retains exactly raw10:
authorization, custody raw7, before-vector and grant. This is not the older
[preparation-only raw7](public-registration-finalization.md), and cannot
retroactively authorize that older plan.

The [finalization record codec](../serverware/control_plane_registration_finalization_records.py)
uses magic `SWCPF001`, family `registration-finalization`, selector
`webauthn.registration.finalize` and local identity domain
`serverware.controlPlaneRegistrationFinalizationGrantRecord/v1`. Its frame has
the two-byte source length, original ASCII source, ten eight-byte big-endian
lengths and exact bodies. Per-object, raw7-group and combined 64 MiB limits are
checked before slicing or joining bodies; the maximum header is 346 bytes.
No existing frame or content-identity domain changes.

`append_registration_finalization_preparation(originals, *, evidence_local_digest)`
exists on the journal and private cold client. It requires an already complete
evidence-grant/signer preparation, rereads its actual association and originals,
and checks capacity for the missing finalization record plus marker before
publication. Existing legacy marker reserves are preserved.

```text
existing evidence grant + signer originals + their association (reread)
  -> publish finalization raw10 record
  -> publish finalization-associated-<finalization digest hex> LAST
  -> return actual finalization grant local ID
```

The [finalization association codec](../serverware/control_plane_registration_finalization_associations.py)
uses `SWCPM001`, a two-byte source length, source ASCII and three raw32 local
digests: finalization grant, evidence grant and signer exchange. Its maximum
is 362 bytes. The three identities must be distinct and share the original
source; the evidence association must already bind that exact signer. The
small marker avoids duplicating the evidence/signer inventories and preserves
their existing local IDs. Each publication uses the existing protected
file/fsync/no-replace/directory-fsync/readback path.

The last marker is the local commit point. Interruption can leave durable
orphan originals or follow a completed publication; it never triggers cleanup,
re-signing, automatic retry or reassociation. An explicitly repeated exact
append is idempotent after readback; conflicting linkage is rejected.
`load_registration_finalization_preparation(finalizationID)` returns exactly
`(finalization PreparedRecord, evidence localDigest, (evidence PreparedRecord,
signer PreparedRecord))` only after rereading both association markers and all
three originals. Recovery/load reject dangling, changed or cross-family/source
links. A standalone original without its final marker is not a complete
finalization preparation.

This is retention only: zero legacy attempt/observation space is reserved, and
attempt, observation, legacy forward and reconciliation actions reject the
family. No finalization reserve, SQL attempt, authenticated outcome or OIDC
activation is implied. The lower-level association authenticates no signatures,
business evidence, permission or currentness; genuine replay remains a separate
prerequisite on use. This path is source-only, unbuilt and unexecuted.

## Retained finalization reservation

`append_registration_finalization_reservation(finalization_digest, originals)`
on the journal and cold client stores one exact returned raw3: signed reserve,
snapshot and state acknowledgment. The real caller must authenticate these
originals first; storage performs only bounded carrier and local association
checks. It requires the actual completed finalization grant/evidence/signer
chain and rereads both markers and all three original records.

The distinct [codec](../serverware/control_plane_registration_finalization_reservation_records.py)
uses magic `SWCPV001` and identity domain
`serverware.controlPlaneRegistrationFinalizationReservationRecord/v1`. Its
frame binds the retained original source token and finalization-grant raw32
local digest, then three u64 lengths and exact bodies. Caps are the actual
finalization reserve transport's 256 KiB request, 16 KiB snapshot and 16 KiB
acknowledgment; the maximum header is 322 bytes. No prior format, family,
content identity or source token is rewritten.

Publication uses `finalization-reserved-<finalization grant digest hex>` only
after the complete association exists. Exact bytes consume the existing quota
and one bounded physical slot, without consuming another record's reserved
legacy marker capacity. The existing no-replace, file/directory-fsync and
identity/readback checks apply. An exact repeat is idempotent; conflicting
originals or changed linkage fail and poison the owner. Late failure can follow
durable publication and never authorizes automatic network retry.

`load_registration_finalization_reservation(finalization_digest)` returns
`None` only after rereading a valid complete association with no reservation
slot. Otherwise it returns the ordinary frozen `FinalizationReservationRecord`
with `source_revision`, `finalization_digest`, exact `originals` and local
`digest`. Recovery/load reject missing, changed, cross-source or wrong-family
references. Absence is not proof of remote failure; presence is not signature
verification, independently current pending-head authority or caller consent.

This slot adds no attempt marker, SQL dispatch, legacy forwarding/reconcile
action, completed credential or OIDC activation. Existing metadata inventory
still shows the separate prepared records, not a new readiness badge. The
sixth [portal action](portal-registration-handoff.md) is explicit and separately
authorized; it does not chain from grant preparation. This path remains
source-only and unexecuted.

## Finalization SQL attempt and outcome

The journal and cold custody client expose separate fixed-purpose methods:

- `claim_registration_finalization_sql_attempt(finalization_digest)` returns
  `None` only after publishing the irreversible local claim. It requires the
  complete finalization/evidence/signer association and an existing original
  reservation, all reread under the actual journal lock. Every duplicate claim
  rejects, including after restart, uncertainty or a missing response.
- `append_registration_finalization_sql_outcome(finalization_digest, originals)`
  stores the first exact bounded unsigned SQL raw4 and returns its local content
  digest. It requires the claim. An exact repeat is idempotent; conflicting
  originals fail and poison the owner, never replace the first observation.
- `load_registration_finalization_outcomes(finalization_digest)` returns the
  ordinary frozen `FinalizationOutcomes(source_revision, finalization_digest,
  sql_attempt, sql_outcome)`. Each present record contains `source_revision`,
  `finalization_digest`, fixed `kind`, exact immutable `originals` and local
  `digest`. Even an empty result requires rereading the complete original chain;
  any present claim/outcome also requires the original reservation.

The [separate codec](../serverware/control_plane_registration_finalization_outcome_records.py)
uses `SWCPX001`, kind index `0` for `sql-claimed` (empty raw0) and `1` for
`sql-outcome` (raw4). Content identities use distinct
`serverware.controlPlaneRegistrationFinalizationSqlClaimRecord/v1` and
`serverware.controlPlaneRegistrationFinalizationSqlOutcomeRecord/v1` domains.
The frame retains the original source token and finalization-grant raw32 digest,
then fixed-count u64 lengths and exact bodies/EOF. It accepts only the actual
finalization SQL transport carrier: `observed-commit` with two locators and an
unsigned marker, or `uncertain` with both locators present or both absent and no
marker. Claim frames are at most 299 bytes; outcome frames are at most 4584
bytes (4253 body bytes plus a 331-byte header). All lengths precede body slicing.
The older evidence outcome schema, magic, kind indices and domains are unchanged.

Publication uses `finalization-sql-claimed-<finalization grant digest hex>` and
`finalization-sql-outcome-<finalization grant digest hex>`. Existing no-replace,
file/directory-fsync, identity/readback, owner/PID, quota and singleton-lock
protections apply. Recovery rejects missing prerequisites, changed originals,
wrong family/source and conflicting linkage. The unchanged `7 * maximum_records`
scan ceiling includes these slots; finalization records now use at most five
physical files. No legacy attempt/observation reservation is consumed or cleared.

These methods do not admit signatures, invoke SQL, authenticate the unsigned
marker or establish currentness. They impose no invocation clock, so a bounded
late, uncertain or semantically rejected response can be preserved under the
same real owner/journal protections before later semantic admission. A missing
outcome, retention error or late failure never establishes no remote effect or
authorizes another send. No claim is cleared; no completion, credential success,
OIDC activation or automatic recovery follows. This remains source-only,
unbuilt and unexecuted.

## Bounded registration completion reconciliation

The separate [completion recovery path](registration-completion-recovery.md)
can preserve a later acknowledged response without replacing an original
uncertain completion. The existing outcome codec appends kind index `4`,
`completion-reconciled`, using the exact bounded completion raw4 carrier and
requiring its first original to be `acknowledged`. Existing kind indices,
original bytes, source revisions and content identities are unchanged.

`CustodyJournal.append_registration_completion_reconciliation(local_digest, originals)`
and the corresponding custody-client method require the actual complete
signer/grant preparation, its irreversible local SQL claim and a retained
original `uncertain` completion outcome. They publish one separate immutable
slot. Exact duplicate originals are idempotent; a conflicting response fails
and poisons the journal. No original, association or SQL claim is overwritten
or cleared, and no additional SQL dispatch is authorized.

The real recovery facade verifies the original signatures and complete
historical pending/completion scope **before** append. Storage checks only the
bounded carrier and local prerequisites; `acknowledged`, a local content ID or
`load_registration_outcomes(...).completion_reconciled` is not authentication,
currentness or permission. Reuse still requires genuine original verification.

Recovery and load recheck the fixed kind/filename, source and prerequisite
relationships. The record uses the existing byte quota and protected atomic
publication/readback/fsync paths; the scan is bounded by
`7 * maximum_records`, with legacy marker reservations unchanged. Publication
uncertainty is not retry permission, and local durability is not hostile-host
anti-rollback protection. This source-only addition provides one reconciliation
slot, not a mutable latest-result log, credential finalization or a new legacy
forwarding/reconcile family.

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

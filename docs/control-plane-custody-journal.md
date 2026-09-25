# Opaque caller custody journal

Caller storage and private forwarding at authority source `.117`; unbuilt and
unexecuted. Local storage remains separate from signed custody/replay authority.

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
                -> one explicit caller-to-relay-to-verifier exchange
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

## Integration still required

Deployment provisioning of the caller directory and signed descriptor inventory,
public invocation/preparation, authenticated lookup-based reconciliation, and
business successor orchestration/execution remain unfinished. The private
client is not automatically installed into control-plane startup or public HTTP
routes. This source path has not been built, launched or exercised.

The [historical resolver](authority-historical-replay.md) supplies a separate
trust-admission boundary; these opaque stored bytes cannot replace it. Explicit
caller recovery, independent provisioning and frozen build/runtime verification
remain required.

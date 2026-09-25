# Current-root decisions and trust boundaries

These are the `.133` current-root decisions with `.134` computation/storage,
`.136` read-only completion and `.138` signed lookup/reconciliation, separate
from the existing replay-witness protocol. This is source-only work, not an
executed or provisioned authority, production approval or successor-execution
permission. See the
[integration boundary](authority-current-root-witness-integration.md) for the
remaining database and executor work.

## Independent enrollment, distinct authorities

A dedicated root signs enrollment of a stable database identity, frozen
generation and complete initial vector. Enrollment also pins separate Ed25519
computation, completion and state keys with their measurement identities.
Caller vectors, a DSN, an empty directory or a matching digest cannot create
that enrollment. Initial population and root provenance remain independently
admitted facts.

The computation key authorizes an exact proposed transition; the completion
key asserts completion of that same pending decision; the state key signs the
durable decision receipt. These roles are distinct, not substitutions for
generic response keys. A signature proves the enrolled producer's assertion,
not native/TEE measurement or SQL commit by itself. Real mutation/projection
proofs and purpose-bound postcommit assurance remain separate prerequisites.

Source `.134` now supplies [actual six-operation plan replay and reserve
production](authority-current-root-computation.md), not merely a computation
signature helper. It produces a distinct computationSnapshot/v1 commitment;
it does not reinterpret revocation Snapshot/v4 or admit an original capability.
Its explicit `capabilityDigest` is scope only. Trusted measurement and cold
signer/serving ownership remain unimplemented.

The complete-vector codec and [delta compatibility check](../serverware/authority_current_root_delta.py)
bind all source tables/profiles and preserve nonwritable descriptors. Primary
revisions advance per row mutation; counted revisions advance per event with
an old or new member. Neither advances merely once per transition, and positive
advances may preserve root/count. Compatibility does not prove the actual
mutation events or their resulting roots.

## One pending decision

The implemented state flow is deliberately narrow:

`enrolled complete vector → signed reserve → one durable pending decision → signed completion → next complete vector`

Reserve binds the exact predecessor, intended after-vector and transition
identity under the enrolled computation key. Completion matches the retained
pending identity under the separate completion key. The original request and
state-signed receipt are durably appended before a response is returned.
Reserve leaves capacity for completion; reaching a quota cannot justify
discarding an unresolved decision.

[`authority_current_root_authorization.py`](../serverware/authority_current_root_authorization.py)
authenticates original root enrollment and reserve/complete controls on the
caller's work. `_verify_request_on_work` checks the supplied evaluation instant;
`_verify_historical_request_on_work` verifies original signatures, intervals,
scope and vector/byte commitments without sampling a clock or renewing them.
Completion binds original opaque writer-receipt bytes, not proof that SQL
committed. Standalone receipt verification does not establish durable publication.

Source `.136` supplies a [fixed committed-state completion
producer](authority-current-root-completion.md): genuine historical pending,
plan and grant admission, followed by an actual read-only marker/full-vector
observation. It requires exact expected-marker/after-vector equality and normal
database closure before the enrolled completion key signs the complete control.
The inner observation is unsigned on its own. A fresh completion can follow
grant expiry without renewing execution authority or clearing unresolved state.

[`CurrentRootDecisionOwner`](../serverware/authority_current_root_decisions.py)
takes the actual journal, original enrollment/root key, state private key and
independently current `expected_sequence`/`expected_head_digest`. Its fixed
recovery validates every request/receipt and replays state before requiring the
exact checkpoint. `apply(request_bytes, transport_deadline_ns=...)` checks
freshness for new decisions, joins pending/ancestry/vector identities and
publishes before returning original receipt bytes. `inspect()` returns unsigned
local metadata; `close()` releases the owner.

A deadline failure after publication does not roll the durable decision back
and is not evidence that nothing was recorded.

Source `.137` adds [purpose-bound Unix-socket serving and durable completion
delivery](authority-current-root-delivery.md). The serving core passes its
peer-admitted action to the actual owner's `expected_action` restriction;
the owner joins the genuinely authenticated request before replay or new
publication, without a second parser allowance. The separate delivery journal
retains exact request/acknowledgment originals and cannot declare its own latest
checkpoint or refresh an expired, never-accepted request.

Source `.138` adds `lookup(query_bytes, transport_deadline_ns=...)` under the
actual owner's existing lock and journal-continuity checks. It signs a fresh
nonce/query-bound observation of actual state and history without appending a
decision. `accepted` carries the unchanged original historical receipt;
`notRecorded` is only a statement about that serialized history, not SQL
noncommit or retry authority. The completion-peer-only transport and explicit
[delivery reconciliation statuses](authority-current-root-delivery.md#explicit-read-only-reconciliation)
do not replace independently current startup checkpoints or hostile-host
antirollback protection.

An exact historical replay returns the original recorded decision/receipt; it
does not obtain a new fence or renew a lifetime. Pending state survives expiry.
There is no abort, reset, generation rollover or independent-currentness endpoint
in this slice. Timeout or a missing database marker is not proof of noncommit and
does not release the pending decision for retry.

## Local durability is not latest-head authority

Startup requires an independently current **exact** latest sequence/head, not a
minimum floor. Recovery must match that checkpoint after validating the complete
local journal. A valid signed older prefix cannot choose its own latest head.
An operator cannot erase or replace the journal, choose genesis or lower the
checkpoint to bypass pending work.

Sequence zero uses the explicitly root-enrolled initial vector and enrollment
identity as its head. Later heads are framed identities of original signed
receipts, not the journal file's raw SHA-256 metadata.

The private directory must be independently provisioned with its exact identity,
owner and permissions. Descriptor binding, a singleton lease, strict immutable
files and durable publication barriers protect the local storage boundary;
they do not establish hostile-host antirollback or independent latest-head
retention. Publication/response uncertainty must be reconciled from the same
records and externally admitted checkpoint, not by automatically retrying a
potentially committing operation.

The implemented [`CurrentRootJournal`](../serverware/authority_current_root_journal.py)
takes a directory FD with pinned device/inode/UID/GID and a limit of 2–1,024
records, at most 1 MiB each. It owns an independent directory description and
nonblocking singleton lease, requires mode `0700`, and accepts only contiguous
immutable mode-`0400`, single-link records. `recover(validate_record)` invokes
the fixed owning service's protocol validator before file/directory barriers;
it creates no genesis. `append(raw_bytes)` publishes once and returns only
sequence/digest/byte-count metadata. Unknown files, discontinuity or ambiguous
publication fail closed; there is no cleanup, reset or automatic retry.

## Still not connected

No independently admitted cold-start entrypoint, listener, protected descriptor
provisioning, deployment, native/TEE guarantee or independent latest-head service
is supplied by this source slice. The existing replay-witness purposes and
legacy operation gates are not widened.

Successor SQL execution still needs protected integration of actual fenced
decision/capability admission, same-transaction marker insertion and maintained
complete roots. The marker schema is immutable framework storage with executor
SELECT only and no insert function. The `.136` completion reader has a separate
fixed role with SELECT on only the marker, primary roots and counted heads; its
actual postcommit producer does not supply cold configuration/key custody or
independent latest-head authority. Separate durable delivery and signed lookup
now exist as source, but cold activation and expired-unaccepted recovery remain
unimplemented.
Every application writer must participate or be excluded. Registration evidence
custody and signed planning remain distinct from inserting the business evidence
row or finalizing a credential. This source-only work has not been built, tested,
imported or run;
no startup or SQL execution is claimed.

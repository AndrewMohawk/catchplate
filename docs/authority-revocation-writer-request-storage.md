# Immutable revocation writer request storage

Status: source implementation and read-only review only. No schema, role,
native fixture or service path has been executed for this source. This table
retains a request; it is not a signed acknowledgement or execution receipt.

`policy_authority_revocation_writer_requests` is one complete, immutable
22-column row. Its global primary key is the stable verifier intent envelope
ID. The planner relay envelope ID and execution envelope ID each have a global
unique constraint. Configuration, generation and signing-key identities are
row data, never part of those global identity keys: a rotation cannot create
another row under an already-used identity. Source `.67` additionally declares
a five-column unique tuple over intent/configuration/generation/source solely
as the referenced key for the immutable ACK child's deferred foreign key.

The row stores the exact original intent, relay and detached historical
expectations as canonical unpadded base64url, each with a SHA-256 digest and
byte count. The two controls retain their existing 4 MiB local bound; history
retains its existing 64 MiB local bound. These are storage checks, not a promise
that all maxima fit the unchanged shared verification budget. No original
plan or evaluation-context body is duplicated here.

A deferred composite foreign key binds planner transaction ID, `revocation-v4`
protocol and retained-record digest to the existing retained-plan sidecar.
A second deferred composite foreign key binds execution envelope ID and planner
transaction ID to the same pair in the execution table. The latter gains a
matching unique constraint; neither relationship cascades updates or deletes.
No reverse request requirement is imposed on older planner/execution rows.

Every field is required on insertion. The row also carries the admitted
configuration/generation pins, planner/verifier key digests, original stored
plan timestamp and source revision. The action must compare the signed proposed
timestamp with that stored timestamp even on first request attachment. The
signed cutoff remains in the original intent; no unsigned replacement cutoff
is stored. Database checks validate shape and references, not signatures,
digest recomputation, clock truth, measured configuration or semantic replay.

The table belongs to the existing immutable/framework custody inventories.
Actual installed guards reject UPDATE and DELETE, including no-op rewrites.
The source-owned writer catalog contract grants only SELECT and INSERT; this
does not grant executor mutation, verifier reads, business-root tracking or a
new operation kernel. SQLite receives an explicit INSERT-denial trigger. Both
existing offline replacement paths reject this table and require a separately
reviewed migration rather than synthesizing request provenance.

The contract and columns are bound into the operation and metadata source
manifests, and the changed fixed writer privilege query is bound into schema
and owner-profile digests. Existing native test IDs are retained: the catalog
fixture originally added this twelfth table to all existing privilege controls
(the separate `.67` ACK child is the thirteenth), and the
retention fixture extends its existing structural cases for deferred parent
links, complete rows, global rotation conflicts and immutability. Opaque native
fixture bytes are deliberately not authenticated requests.

Request lookup, exact-original comparison and insertion belong to the same
common writer savepoint as both genuine retain/reserve replays. No fifth
transaction manager, cached-success token, public purpose, transport framing or
resource-limit expansion is introduced by this storage contract. Source `.67`
adds [signed ACK custody](authority-revocation-writer-acknowledgment.md) after the
complete request readback, still inside the same common scope.
See [writer composition](authority-revocation-writer-composition.md) and
[writer permissions](authority-planner-writer-permissions.md).

The fixed runtime suffix performs lookup before either replay, derives the
record/key links only after both actual replays, then always reads and compares
the complete row. An INSERT conflict is not success without that readback.
Missing, partial or changed rows fail; there is no update or repair path.
Existing exact rows still require both replays. A failure before common-scope
release rolls back all six original custody sets and the separate ACK child,
even if caught inside the outer writer transaction. Errors after commit remain
uncertain and need reconciliation.

The same cumulative work pays for two stable-ID frames and three original-body
hashes, the three real base64 codecs, driver-row ownership, SQL parameter
ownership, seven replay-output linkage comparisons and exact row comparisons.
Retry adds its real lookup ownership and comparison work before the replay
peaks. This is five added hashes, not a second eight-hash authentication pass;
no successful authentication or proof object is accepted as an alternative input.
The request row itself is neither an ACK nor an execution capability. The `.67`
authenticated suffix returns a triple containing the ordinary retained receipt,
reservation and exact stored ACK bytes only after normal common, outer and
connection exit. The older independent-input public atomic API retains its pair.

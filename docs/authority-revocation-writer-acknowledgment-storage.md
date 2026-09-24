# Immutable writer acknowledgment storage

Source `.67` adds a PostgreSQL-only acknowledgment child for the immutable
[writer request](authority-revocation-writer-request-storage.md). This is
unbuilt and unexecuted source. The row is custody data, not evidence that a
signature was verified, a transaction committed, or an execution occurred.

## Complete original custody

`policy_authority_revocation_writer_acknowledgments` has ten required columns:

| Columns | Binding |
| --- | --- |
| `ack_envelope_id`, `intent_envelope_id` | Global ACK primary key and unique request intent |
| `configuration_digest`, `generation_sequence`, `generation_digest`, `source_revision` | The immutable request's exact historical scope |
| `writer_response_spki_digest` | Dedicated response-key pin; not key enrollment |
| `exact_ack_base64url`, `exact_ack_bytes_digest`, `exact_ack_byte_count` | Original signed wire and its stored byte anchors |

The stable ACK identity does not acquire a new namespace when configuration,
generation or keys rotate. Both its primary key and the unique intent link
therefore continue to conflict across such changes. This promises one durable
row per intent, not globally exactly one signing attempt: a losing concurrent
transaction can sign before it aborts.

The five-column foreign key joins intent, configuration, generation sequence,
generation digest and source revision to a matching unique key on the request.
It is `DEFERRABLE INITIALLY DEFERRED`, with PostgreSQL's default `NO ACTION`
update/delete behavior and no cascade. This permits insertion within the same
owning transaction while rejecting missing or crossed request scopes at the
constraint boundary. The request remains linked to its retained-plan and
reserved-execution parents; the ACK does not duplicate those large originals.

All ten fields are required. Digest and ID spellings are canonical lowercase
SHA-256 strings. Generation is a positive PostgreSQL BIGINT. The ACK wire is
bounded independently to 2 through 16,384 bytes; its unpadded base64url column
has exact encoded length, alphabet and tail-bit constraints. These SQL checks
do not compute the byte digest or verify a signature. The fixed application
path must still bind and authenticate the actual original bytes.

There are no execution status, terminal response, commit time, currentness or
witness columns. Signed contents and byte custody must not be interpreted as
an execution receipt or a historical authorization bypass.

## Storage and privilege closure

The table is framework custody, not a business/authorization root or an
operation mutation grant. It belongs to the existing immutable table inventory,
which drives schema manifests, runtime read-only restrictions and immutable
update/delete guards. The planner writer receives only SELECT and INSERT;
the same thirteen-table catalog/sealing contract denies extra privileges,
PUBLIC/column grants and grant options. No new executable function is added.

SQLite explicitly rejects ACK inserts. Existing stores containing ACK custody
require a separately reviewed migration; neither general migration path may
synthesize, discard or cascade it. The offline v8-to-v9 source inventory also
classifies this as a new v9 table, not legacy evidence to promote.

The source-owned row contract, operation manifest, complete schema and owner
profile bind this inventory. Source `.67` has twenty-one v9 DDL revision pins.

## Authored controls and remaining boundary

The existing native retention fixture extends four preserved test IDs to
cover child-before-parent deferred admission, missing and crossed scope,
required fields and canonical transport, immutable rows, and global ID/intent
conflicts under changed key/configuration values. It uses deliberately opaque
structural bytes, not a substitute valid ACK or signing result. Positive shape
variants and the disposable schema are rolled back. The native catalog fixture
extends its literal grant inventory without changing method IDs, suites or
resource allowances. No native fixture has executed for this source.

The configured application path must perform the actual request authentication,
both genuine retained replays and ACK validation/insertion inside its common
savepoint. Only exact stored bytes may leave after normal outer transaction
and connection exit. A commit/exit failure can leave durable rows without a
returned ACK; recovery cannot assume rollback or regenerate a different wire.
The schema alone establishes none of these runtime claims. Public transport,
historical ACK lookup and production signer provisioning remain separate work.

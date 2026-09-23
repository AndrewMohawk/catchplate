# PostgreSQL audit initialization preparation reader

Status: source implementation and read-only review only, unbuilt and unexecuted.
`authority_audit_initialization_postgres.prepare_audit_capacity_initialization_from_postgres`
now feeds actual PostgreSQL rows and persisted radix proofs into the real
[initialization preparation](authority-audit-initialization.md). It is not a
counter installer, current-root authority, signed checkpoint producer or
one-use decision consumer. The result still has `installationPermitted: false`.

## Transaction and trust boundary

The caller supplies a live psycopg connection in an active, non-autocommit,
SERIALIZABLE read-write PostgreSQL 16 transaction with UTF8 server/client
encoding. Idle, failed, read-committed and read-only transactions are rejected.
The reader never begins, commits, rolls back or retries a transaction. It closes
its own cursors; transaction completion and error recovery remain the caller's
responsibility. Read-write status is needed for locking, not a DML grant.

The explicit context/root expectations are copied and validated. The reader
locks, in order, the outbox, bounded aggregates, authenticated roots, leaves,
nodes and root-revision tables in ACCESS EXCLUSIVE mode. Base tables precede
root locking, as they do in the production AFTER-trigger path. It then selects
both exact roots `FOR UPDATE`, checking table, revision, digest, leaf count,
64-level/16-way dimensions and the source query-manifest digest. Physical leaf
counts must match each descriptor, rejecting orphan leaf metadata; those counts
are database consistency checks, not independent cardinality authority.

**Locks do not refresh a previously established transaction snapshot.** The
initial control/context SELECTs may establish that snapshot. PostgreSQL's repeatable-read
and serializable rules reject row locking after a concurrent committed change
to the target row; ordinary serialization failures propagate without internal
retry. This is why both trigger-maintained root rows are locked, but it does
not turn the snapshot into independently authenticated current state. See the
official [PostgreSQL 16 isolation contract](https://www.postgresql.org/docs/16/transaction-iso.html)
and [locking contract](https://www.postgresql.org/docs/16/explicit-locking.html).

An eventual admitted initializer must establish its real all-writer fence
before creating the snapshot and must separately admit the complete schema,
function definitions, privileges, database generation, current root authority
and commit-time evidence. These six table locks are not that measured fence or
complete schema/ACL closure. The namespace is an exact lowercase ASCII SQL
identifier, defaulting to `serverware_metadata`; the native fixture uses an
explicit random schema, not SQL rewriting or a patched registry.

## Actual stream and proof path

Every base outbox identity enters the stream, regardless of status. Enumeration
does not start from the leaf table and uses no inner join that could hide an
unindexed base row. The database sorts only the ID and production
`AuthenticatedKey/v1` digest, not full event bodies. A non-holdable named cursor
fetches one identity at a time. A separate cursor on the same connection fetches
the exact full row and calls the real `derive_multiproofs` singleton reader.
All 65 leaf/child-set reads use the actual persisted tables.

The reader recomputes every enumerated key independently in Python, requires
strict digest order and the exact accepted outbox count, then streams the
selected-row/proof pairs into the real complete-population preparation. Missing
leaves, extra stored leaves, changed full rows, bad nodes and short/extra streams
cannot become a successful prefix. The exact global aggregate key must be
absent in the base table and its real nonmembership proof must validate. Other
aggregate rows may exist and remain unchanged.

The pure preparation still reconstructs the complete outbox root, calculates
the exact compact 17-field initial counter and its prospective root transition,
and returns immutable canonical bytes. The adapter performs no INSERT, no
manual after-root assignment, no nonce consumption and no signature admission.
Matching database counts does not remove the independent aggregate-cardinality
and currentness requirements.

## Resource contract

`AuditInitializationReadLimits` requires explicit row, total-byte, read-command,
per-statement, lock, total elapsed and per-record limits. Exact integers only;
rows may be zero, other limits are positive, timeouts cannot exceed one day,
and record acceptance cannot exceed the source 64 MiB ceiling.

Each SQL command and each named-cursor FETCH is charged with its preceding
timeout-setting SELECT: two command units. That SELECT re-arms statement and
lock timeouts using the remaining monotonic deadline, and sets
`row_security=off` so row-policy filtering cannot quietly omit rows. It does not
grant a role RLS bypass; PostgreSQL may reject access instead. Transaction-local
timeouts and that setting remain until the caller ends the transaction. Cleanup
CLOSE commands are unconditional and excluded from the read-command budget.
The empty successful path costs 146 command units under this exact source.

The total-byte budget charges canonical returned SQL data, composed row/proof
records and the final preparation; material encountered at more than one step
is charged again. This is a bounded accounting policy, not wire-byte telemetry
or peak RSS. Per-record acceptance additionally checks canonical full rows and
composed proofs. The shared proof reader's key-JSON transport ceiling remains
64 MiB even when a job requests a smaller record-acceptance cap; digest/path
columns have their fixed 71/64-byte SQL projection bounds.

Oversized IDs, full rows and stored proof strings become explicit rejection
sentinels through SQL CASE, never WHERE-filtered omissions or truncated data.
Full-row size evaluation, key sorting and detoasting still perform work inside
PostgreSQL. Named fetches do not themselves bound the server's sort memory or
temporary storage. The total deadline is checked around commands, returned
data, proof work and final preparation; it is not a preemptive interruption of
Python work or a stuck driver/server/transport. The job owner must enforce a
watchdog and database/process CPU, memory and spill/storage limits. The reader
does not raise any online row or proof budget.

## Authored verification and remaining integration

Seven new proof-reader component/source tests cover the namespace and bounded
projection behavior; existing test names remain. The native initializer fixture
uses real production DDL, shared tree functions and triggers, actual stored
proofs and independent row/tree/preparation oracles. It covers mixed/Unicode and
empty/history populations, preserved other aggregates, inconsistent base/leaf
state, corruption, existing counter, session/resource boundaries, and caller
transaction ownership. Its separate source check does not execute the guarded
authority service or claim a successful production launch.

Nothing has run. The new native file remains in the external-engine inventory;
as a newly changed excluded native test it blocks preparation until explicitly
covered, not a passing exclusion. All `goal.md` frozen-source, controller,
dependency, cleanroom and sequential no-build prerequisites remain unchanged.

This reader closes the real database-to-preparation path only. Joining it to
purpose-specific signature verification, independently enrolled decision
storage, all-writer exclusion and atomic row/tree/materialization receipt
installation remains required. No new external backend was selected or
provisioned. See the [independent decision requirements](authority-audit-initialization-decision.md).

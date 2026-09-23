# Local PostgreSQL initialization candidate storage

Status: source implementation and read-only review only; unbuilt, unexecuted,
not deployed. This is a transactional storage prerequisite for the
[independent decision protocol](authority-audit-initialization-decision.md), not
an enrollment authority, external anchor or installer. Its sole record state is
`RECORDED_UNANCHORED`, with `installationPermitted: false`. It never produces
`COMMIT_DECIDED`, `APPLIED` or a signed installation receipt.

## Stable identity and owner provisioning

`LocalInitializationEnrollment` represents independently supplied expected
database identity/generation, generation sequence/predecessor, backend
incarnation, source/schema/initializer/ancestry bindings and complete trust
context, including both public-key pins. The global counter identity is fixed
by source. Construction and its self-digest validate representation only;
there is no trusted enrollment loader or provisioner. Caller-selected labels
are not independent identity, physical separation or authority.

The fresh DDL renderer in `authority_store/audit_initialization_store_sql.py`
defines two dedicated tables without creating a namespace, enrolling a database,
silently accepting old tables, migrating anything or running SQL:

- `initialization_enrollments` is keyed solely by stable database identity.
  Canonical bytes/digest pin generation and counter identity. Its mutable head
  is sequence zero/enrollment digest or sequence one/candidate digest. A newer
  generation is not a new uniqueness key or fresh entitlement.
- `initialization_candidates` has the same primary key and a composite foreign
  key to exact enrollment identity/digest. It retains request/candidate
  commitments and exact bytes, once per identity, not once per nonce.

There is no runtime enrollment, missing-head genesis, reset, delete, expiry
reopening, generation-handover or anchor setter. Missing or contradictory state
denies. Changing pinned enrollment bytes currently denies; admitted generation
handover and cross-generation lookup must preserve consumed/unresolved state.

The optional grant renderer revokes direct PUBLIC/runtime table and column
privileges, then grants schema USAGE, SELECT on both tables, UPDATE only on head
columns and INSERT only on candidates. It grants no enrollment INSERT, candidate
UPDATE/DELETE, DDL or grant option. This does not establish ownership, effective
inherited privileges or schema admission by itself. Both public store operations
now require the separate observed admission described below. Owner/superuser
power and backend restoration remain outside the append-only runtime claim.

## Mandatory observed database admission

Both operations require an `InitializationStoreDatabaseIdentity`: expected
namespace, database name/OID, cluster system identifier, separate runtime and
owner role names/OIDs, and backend incarnation digest. Exact bounded primitives
are copied and revalidated; namespace and incarnation must match the call and
enrollment before SQL. These are independently supplied expectations, not a
trusted identity loader or self-authenticating authority. Cluster identifiers
and OIDs do not prove physical independence or distinguish a restored clone.

`authority_store/initialization_store_access.py` reads the actual session and
catalogs on every recording and lookup. It requires the pinned LOGIN runtime as
both current and session user, a distinct NOLOGIN owner, no privileged flags or
role memberships in either direction, matching database/cluster identities,
UTF8/PG16, current database collation version and normal trigger execution.
The runtime must have no privilege to change `session_replication_role`.
Effective privileges and raw schema/table/column ACLs must match the exact
source grant contract, including grantors and no grant options. Runtime database
CREATE/TEMP privileges deny; the dedicated database provisioner must remove
default PUBLIC TEMP access. Namespace and table ownership must match the owner.

Actual `pg_control_system()` execution is required. A trusted provisioner must
separately grant the runtime EXECUTE on that exact catalog function; neither the
admission code nor the table-grant renderer widens grants automatically. Missing
permissions fail normally, not as a skip or a successful identity observation.
See PostgreSQL's [privilege and control-data functions](https://www.postgresql.org/docs/16/functions-info.html).

`authority_store/initialization_store_structure.py` admits the source-owned
two-table contract without creating a comparison schema. It checks ten exact
columns, fifteen constraints, three constraint-backed unique btree indexes and
the four built-in internal foreign-key triggers. Constraint definitions are
fixed non-pretty PG16 forms, not definitions learned from installed objects.
It rejects dropped/default/generated/inherited columns, typed/partitioned or
nonpermanent tables, RLS, rules, extra indexes/triggers, unvalidated constraints,
changed foreign-key actions, and foreign namespace objects or extension
membership. Table row/array types are the only namespace types admitted.
The exact deparser forms and successful least-privilege path remain unexecuted;
native positive coverage is required before any compatibility claim.

There are seven fixed read queries per admission module, with count-plus-one
sentinels and bounded definition transport. These observations assume trusted
administrator stability: they do not freeze concurrent privileged DDL or
GRANT/REVOKE, audit all privileged functions elsewhere in the database, or prove
an independent rollback-resistant latest head. There is no reusable admitted
identity token, grant repair or schema-repair fallback.

## Recording and exact historical lookup

`record_local_initialization_candidate` takes a dedicated store connection, a
separate caller-owned metadata connection, original checkpoint/authorization
bytes, enrollment, store identity, trust/expectation/roots, explicit verification
time, both read limits and namespaces. It owns revalidated input copies and
nested pins, matches static facts to enrollment, and genuinely preflights signed
intent before SQL.

Within its store transaction it performs both mandatory admission checks before
reading any candidate or invoking the metadata verifier, then locks and validates
exact enrollment and head/candidate correspondence. An already retained identical request returns
the original historical candidate without re-reading evolving metadata;
different bytes conflict. For a new candidate it calls the actual
[signed PostgreSQL verifier](authority-audit-initialization-postgres.md) over
real metadata rows/proofs. It accepts no preconstructed Evidence or public
verification callback. The metadata reader gets the smaller of its elapsed
limit and the store's remaining budget.

Requests retain original signed envelopes as exact hex. Candidates bind database
identity, enrollment, request, predecessor head, sequence and actual evidence.
Candidate INSERT, conditional head advancement and real stored byte/head
readback share one transaction. The metadata transaction is never committed,
rolled back or retried here; its locks/settings stay caller-owned.

Recording requires fresh intent at supplied `now_epoch_ns`. Expired recovery
uses `lookup_exact_local_initialization_candidate`, which has no clock or
metadata connection. It returns the retained record, or None only for a present,
pinned and internally consistent locally unused enrollment. Neither is new
installation authority or independently current state. Missing, conflicting or
inconsistent state denies.

Historical lookup verifies original signatures against retained pins, archival
v1 envelope/evidence/request commitments, pinned identity/static bindings,
consistent historical source/profile and preparation/row/before-after links.
It does not apply today's source revision or envelope validity time to history
or re-prove the old inventory. Original time and bytes remain unchanged. This is
archival integrity, not current policy/revocation, root freshness, physical
truth or permission to repeat an INSERT. Representation classes and self-digests
are not authority tokens.

## Transaction, durability and resources

The store connection must be exclusively owned for the call, initially IDLE,
non-autocommit, PG16 and distinct from metadata. Active transactions deny: a
nested Psycopg transaction may be only a savepoint. The store uses a top-level
SERIALIZABLE read-write transaction, requires UTF8 client/server, a primary,
`fsync=on`, `full_page_writes=on`, `synchronous_commit=on`, and returns only after
the context's commit acknowledgment. See the
[Psycopg transaction contract](https://www.psycopg.org/psycopg3/docs/basic/transactions.html).

Post-entry errors close the store handle after the context's rollback attempt.
Errors during/after attempted commit conservatively become
`LocalInitializationOutcomeUnknown`: closing cannot undo a possible commit.
Keep writers fenced and use fresh exact lookup, never reset/reinstall from
absence. SQL/serialization errors propagate without internal retry. Input or
preflight rejection and expired pre-entry deadlines leave an idle handle alone.

This is conditional local persistence, not protection against administrator
rollback, lying storage, unsafe failover or independent latest-head loss.
Synchronous commit also depends on replication configuration; see the
[PostgreSQL 16 WAL settings](https://www.postgresql.org/docs/16/runtime-config-wal.html).
No independent-storage assurance or live deployment is established.

Local settings use `SET LOCAL`, not a `SELECT set_config` that would establish
the serializable snapshot early. Exact `LOCK TABLE ONLY` ACCESS SHARE locks on
both store tables precede the first SELECT. This is compatible with the runtime's
SELECT grants and prevents conflicting table replacement, but is not a writer
fence or complete administrative DDL/ACL seal. No table-wide UPDATE grant is
added merely to obtain stronger locks. See the PostgreSQL
[lock privileges and snapshot-order contract](https://www.postgresql.org/docs/16/sql-lock.html).

Store limits are explicit positive exact integers for statement, lock and total
elapsed milliseconds, capped at one day. The monotonic deadline starts at public
entry; checks precede transaction setup and surround store commands, metadata
verification/readback and commit preparation. Remaining-time SQL timeouts are
rearmed with synchronous-commit, catalog search-path and RLS-off settings; RLS-off
grants no bypass. BEGIN, transaction setup, timeout arming, driver transport and
commit still need an outer watchdog. This is not preemptive interruption, a
peak-RSS bound or a trusted verification clock.

There is a fixed number of indexed store reads/writes, not a history scan. Both
integrity reads use LIMIT 2 and retain invalid rows as rejection sentinels.
SQL CASE bounds returned digests to 71 bytes, enrollment to 16 KiB and candidate
to 4 MiB. In-process checks then validate canonical JSON/types and commitments.
SQL detoasting and backend CPU/memory/storage limits remain
external obligations. No online business/proof budget increases.

## Authored fixture and missing production work

The native fixture requires an externally prepared owned 0700 Unix socket,
PG16/UTF8 with durable-primary settings, and `--disposable-cluster` acknowledgment.
Its direct fixture superuser creates a unique store-only database, NOLOGIN owner
and LOGIN runtime, source schema/grants and enrollment. The prepared disposable
harness must allow the actual passwordless runtime Unix-socket login; no SET ROLE
substitute or HBA-failure skip is allowed. Store operations commit and reopen as
that runtime. Metadata stays rollback-only in the original supplied database,
whose ACLs are not changed. Cleanup closes all tracked connections, then drops
only the exact validated fixture-created database and roles, without FORCE or
backend termination. No engine starts. Both databases use one disposable
cluster, not independent fault domains; never run this on a production cluster.

Controls cover independent full byte/hash oracles, commit/reopen, replay and
expiry/source-revision lookup, conflicts, missing/corrupt state, actual signatures
and metadata proof rejection, limits, and bounded second-connection lock timeout.
New controls cover actual login/ownership, wrong database/role/system-identifier
pins, effective and raw-only grants, memberships, CHECK/index/RLS/owner changes,
an otherwise matching typed table using an external composite,
disabled internal triggers and replaced foreign-key actions. The catalog-drift
helper checks both entry points, unchanged rows, closed failed handles, exact owner
restoration and a successful lookup afterward. There are 36 authored methods:
29 native, 6 pure representation and 1 supplemental source-order check.

The historical head-failure test name is retained, but its extra trigger now
correctly denies during structural admission before candidate INSERT. It no
longer supplies post-write rollback coverage; that gap remains alongside physical
crash, concurrent-winner and lost-COMMIT-ack validation. Effective runtime grants,
deparser compatibility and schema admission have only source-level coverage so
far. No fake successful verifier or commit receipt is used.

Nothing has executed. The newly changed native file is in the external-engine
inventory and blocks preparation until covered by an approved lane; exclusion
is not a passing result. All `goal.md` freeze, immutable dependency/coverage,
controller, cleanroom and sequential no-build requirements remain unchanged.

Trusted enrollment/backend provisioning, administrative stability and
database-wide privileged-code closure, service identity admission, continuously
rollback-resistant latest head, signed anchored
decisions, authenticated materialization, all-writer fencing and atomic
counter/tree/receipt installation remain required. Runtime activation and
counter installation stay disabled. This prerequisite is not completion.

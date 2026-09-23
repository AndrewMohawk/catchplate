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
inherited privileges or schema admission. Owner/superuser power and backend
restoration remain outside the append-only runtime claim.

## Recording and exact historical lookup

`record_local_initialization_candidate` takes a dedicated store connection, a
separate caller-owned metadata connection, original checkpoint/authorization
bytes, enrollment, trust/expectation/roots, explicit verification time, both read
limits and namespaces. It owns revalidated input copies and nested pins, matches
static facts to enrollment, and genuinely preflights signed intent before SQL.

Within its store transaction it locks and validates exact enrollment and
head/candidate correspondence. An already retained identical request returns
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
SQL detoasting, schema validity and backend CPU/memory/storage limits remain
external obligations. No online business/proof budget increases.

## Authored fixture and missing production work

The native fixture requires an externally prepared owned 0700 Unix socket,
PG16/UTF8 with durable-primary settings, and `--disposable-cluster` acknowledgment.
It commits a random store schema, owner fixture enrollment and candidates so
separate-connection readback exercises actual transaction semantics. Metadata
remains rollback-only. Cleanup closes tracked connections and removes only the
exact validated fixture-created namespace. No engine starts. Both connections
use one disposable cluster, not independent fault domains; do not run this
fixture on an existing production cluster.

Controls cover independent full byte/hash oracles, commit/reopen, replay and
expiry/source-revision lookup, conflicts, missing/corrupt state, actual signatures
and metadata proof rejection, limits, real SQL head-update failure with rollback,
and bounded second-connection lock timeout. Pure representations and source-order
checks supplement those controls. No physical crash, lost COMMIT acknowledgment,
effective runtime grants or production schema admission has been verified. No
fake successful verifier or commit receipt is used.

Nothing has executed. The newly changed native file is in the external-engine
inventory and blocks preparation until covered by an approved lane; exclusion
is not a passing result. All `goal.md` freeze, immutable dependency/coverage,
controller, cleanroom and sequential no-build requirements remain unchanged.

Trusted enrollment/backend provisioning, schema/ACL and service identity
admission, continuously rollback-resistant latest head, signed anchored
decisions, authenticated materialization, all-writer fencing and atomic
counter/tree/receipt installation remain required. Runtime activation and
counter installation stay disabled. This prerequisite is not completion.

# Shared primary-tree SQL and native transaction controls

Status: source changes and authored tests only, unbuilt and unexecuted. This
does not supply an initializer, independent roots, one-use ancestry or a
production installation receipt. The full verification gate remains unchanged.

## Production implementation and syntax correction

`authority_store/primary_tree_sql.py` now renders the actual production tree
JSON, length-framed digest, empty-subtree, row-apply and row-trigger functions.
`db._install_policy_candidate_authority_guards` calls those renderers at the
same dependency positions. Root bootstrap, per-table trigger attachment,
function ownership/ACLs, signature inventories and schema admission remain in
their existing installer paths. Rendering itself connects to nothing and grants
no privilege. Namespace input is an exact quoted lower-case identifier of at
most 63 bytes; the manifest digest is exact lower-case SHA-256. Tree dimensions
remain the source-owned 64 levels and radix 16, with the existing 72 MiB SQL
serialization/frame ceiling, not a larger evaluator or transport budget.

The extraction retains the exact original function templates except one
reviewed timestamp syntax correction in `authenticated_apply`. Eleven production
epoch calls previously mixed the qualified function name `pg_catalog.extract`
with the special `epoch FROM ...` syntax. They now use the ordinary qualified
call `pg_catalog.extract('epoch', value)`: ten clock timestamp calls and one
WebAuthn challenge expiry conversion. Operands, casts, multipliers and flooring
are retained with the intended numeric semantics; `date_part` and its
floating-point return are not substituted. PostgreSQL's [special EXTRACT grammar](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/parser/gram.y)
is separate from qualified ordinary function argument lists, and its
[date/time reference](https://www.postgresql.org/docs/16/functions-datetime.html)
documents the numeric extraction semantics. This is a source-grammar correction,
not a passing PostgreSQL execution result.

Persisted tree JSON remains compact literal UTF-8, sorted under PostgreSQL `C`
collation, with the original length-prefixed domain and frame hashing. It is
distinct from ASCII wire JSON and NUL-domain message hashes. The prior source
fingerprints remain pinned: the source-only check maps back exactly the one
reviewed apply timestamp spelling before comparison, not a wholesale fingerprint
refresh. Canonical/empty/hash bytes and all tree serializer call arguments stay
unchanged. The separate SQL wire-domain digest definition remains in `db.py`.

Existing installations still require an explicitly admitted source/function
transition. No current database was repaired, source revision or table DDL
changed, runtime permission expanded, migration receipt repurposed, or activation
enabled.

## Authored native coverage

`scripts/test_authority_primary_tree_postgres.py` uses six exact table declarations
from the production schema sources: outbox, bounded aggregate, and the four
root/node/leaf/revision relations. It installs the five shared production SQL
definitions and real AFTER row triggers, then compares their effects against an
independent full-tree oracle. It does not assign predicted after-root heads.
Explicit empty heads are component setup only, not independently accepted
genesis. This fixture does not run the complete production schema/ACL installer.

Seven authored methods cover:

- Actual table column sets and the independent empty-digest ladder.
- Full-row INSERT/UPDATE/DELETE, Unicode keys/values, all leaves/nodes, root
  counts/revisions, history links and final deletion back to an empty tree.
- Identical UPDATE advancing revision without changing root digest or count.
- Duplicate INSERT leaving all six tables unchanged after savepoint rollback.
- Exact real initialization preparation followed by insertion of its seventeen
  fields through the actual trigger; predicted aggregate after-root matches the
  independent oracle and the outbox rows/tree stay unchanged.
- A deliberate post-write failure rolling back counter, leaf, node, root and
  revision history together, followed by retry within the same test transaction.
- Missing or wrong-manifest root rejection without partial business/tree writes.

History/root timestamps are checked only as nonnegative integer nanoseconds
with PostgreSQL microsecond precision; they are not independently trusted time.
The explicit counter timestamp remains separate. Preparation still returns
`installationPermitted: false`; a privileged component fixture's INSERT is not
an admitted installation workflow.

The externally prepared fixture must provide PostgreSQL 16/UTF8 through an
owned mode-0700 Unix socket. Each test uses one SERIALIZABLE transaction, bounded
statement/lock/idle timeouts and a random schema. Cleanup is registered before
the first query and always rolls back/closes, including setup failure. There are
no commits, engine launches, second sessions or broad schema drops. Injected
savepoint failures are transaction-rollback controls, not physical crash,
concurrency, postcommit recovery or durability evidence.

Six additional pure renderer/source-linkage methods check input validation,
function dependency order, fixed bounds, retained mutation guards and all eleven
epoch spellings. The wire-source partition fixture now reads both source files;
the existing root/wire/global-capacity native fixtures use the shared tree JSON
renderer while retaining the actual separate wire-domain SQL extraction. None
of these methods has run. The new native file enters the excluded real-engine
inventory, where a changed/new excluded test continues to block verification
until the trusted controller supplies exact prepared coverage and cleanup. This
entry is not a passing exclusion or an execution waiver.

## Initializer integration still required

The existing v8-to-v9 migration explicitly requires the new aggregate table to
remain empty. Its completed receipt cannot authorize insertion of this global
counter. A separate versioned offline initializer needs a dedicated immutable
materialization receipt/consumption contract, independently trusted context and
checkpoint production, complete writer fencing and currentness through commit.
One aggregate absence proof still cannot derive aggregate cardinality.

One-use state must be keyed by independently accepted database identity,
generation and the fixed global counter, not just a fresh caller nonce. A
deleted row or restored database is not new genesis. A separately operated
decision authority must durably retain the exact authorized transition before
SQL commit; ambiguity remains recovery-required rather than permission to issue
another decision. A same-database receipt, local journal or static witness floor
alone cannot establish independent rollback resistance.

The eventual database transaction must acquire deterministic exclusive locks
before inventory reading, validate schema and current before roots, invoke the
real signed-evidence consumer, recheck authority after long work, insert through
the real trigger, compare actual row and after roots, and atomically retain its
purpose-specific consumption/materialization marker. Exact committed retry must
return the saved historical receipt even after normal counter evolution, never
reinsert or require today's counter to equal its initial value. Off-host
decision recovery, precommit abort, lost commit acknowledgement, concurrency,
rollback and generation handover still need implementation and controlled tests.

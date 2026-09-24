# Measured verifier read permissions

Status: source implementation and read-only review only. No interpreter, test,
PostgreSQL engine, installation or service verification has run for this tree.
The source change is not evidence of installed privileges, database authenticity
or a successful WebAuthn operation.

## Current read closure

The v9 service reaches `_read_webauthn_authority` when an operation's source
contract requires an assertion. That path reads exactly four metadata tables:

- `webauthn_challenges`
- `webauthn_credentials`
- `webauthn_trust_publication_high_water`
- `webauthn_trust_publications`

The reads resolve a challenge and credential, join the published trust head and
publication, and reject a pending trust publication. This is table-level SELECT
authority; the SQL projections remain narrower than all table columns. The
planner, issuer and executor have separate identities and permission policies.
The private successor root reader additionally observes exactly two metadata
tables: `policy_authority_authenticated_table_roots` and
`policy_authority_counted_index_heads`. It needs no business rows, primary or
counted tree nodes/leaves, dependency-manifest tables, or mutation authority.
Its complete seven business roots, two authorization roots and nine counted
heads are ordinary independently acquired observations, not an enrolled root
checkpoint or proof of currentness at a later execution.

Retained pre-v9 root/replay/outcome helpers have no current verifier dispatch
path and do not justify granting their historical broader table inventory.
Their manifest-table joins remain outside this six-table permission set.

Previously all four metadata ACL-sealing callers omitted the dedicated verifier
role and table arguments. The defaults aliased verifier to runtime, skipped the
separate read grants/checks, and did not preserve an independently granted
verifier identity. This was a source installation gap, not a measured live
failure or a claim that every WebAuthn operation takes this path.

## Coordinated source correction

`authority_contract.VERIFIER_READ_CONTRACT` identifies
`serverware.policyAuthorityVerifierRead/v2`; its frozen `VERIFIER_READ_TABLES`
contains only the four evidence tables and two root/head tables above. The
database facade uses that set directly. An evidence-only v1 installation lacks
required SELECT permissions and must fail the v2 admission; it is not silently
accepted as compatible.

Bootstrap, expected-schema construction, receipt repair and fresh v8-to-v9
migration all pass the dedicated configured verifier role and exact source set.
Before SQL, metadata and expected-schema sealing reject a missing, malformed,
nonmatching or colliding role, or a nonexact table set. The role must be distinct
from runtime, executor, planner, issuer and authority owner. Separate audit and
recovery-witness sealers retain their existing policies.

The existing sealer now reaches its dedicated branch: schema USAGE plus SELECT
on exactly those six tables. Its role, membership, function and relation-ACL
checks remain, followed by the same effective-privilege query used by the live
read path. This does not provision a role, credential, mTLS identity or service.

## Shared connection-admission query

`authority_store.verifier_read_sql` owns one fixed catalog query. Its pure helper
returns the statement and three bound parameters: role, namespace and the sorted
source-owned table list. Names must be exact nonempty strings without NUL and
fit 63 UTF-8 bytes. No caller supplies SQL, an alternate read set or interpolated
identifiers. The query returns at most one violation; any row denies admission.

The query requires the role and namespace to exist, LOGIN without elevated role
flags, schema USAGE without CREATE or grant options, and no database CREATE/TEMP
authority or role membership in either direction. All six required relations
must be real or partitioned tables with full-table SELECT. It rejects:

- Table/column writes or grant options, including on otherwise allowed tables.
- Additional table/column SELECT through tables, partitions, views, materialized
  views or foreign tables in the metadata namespace.
- Every sequence permission, metadata function EXECUTE, and PUBLIC grants on
  metadata schemas, relations, columns or functions.

Privilege inquiries include effective table/column rights, while separate raw
ACL checks reject PUBLIC grants even for an otherwise permitted SELECT. The
checks use explicit true/false comparisons so NULL cannot become permission.
Type-specific CASE branches avoid applying sequence/table inquiries to the
wrong relation kind. These semantics follow the
[PostgreSQL 16 privilege inquiry contract](https://www.postgresql.org/docs/16/functions-info.html#FUNCTIONS-INFO-ACCESS-TABLE).

The existing WebAuthn evidence reader retains its repeatable-read/read-only transaction and exact
configured role/client-certificate checks. SSL and LOGIN must be literal true;
elevated/DDL flags must be literal false. The shared query runs after those
identity checks and before any business SELECT. No SET ROLE, direct business
write grant or new database function is introduced.

The separate private root owner uses SERIALIZABLE READ ONLY DEFERRABLE, exact
current and session role, PostgreSQL version, transaction mode and configured
TLS checks, followed by the same effective-privilege query before either root
SELECT. It does not reuse a planner connection, trace or transaction. Its
service adapter remains private; this grant change does not activate a public
purpose, a WebAuthn kernel, or the retained pre-v9 root helpers.

This is connection-admission evidence for the metadata namespace, not continuous
privilege monitoring, an all-database sandbox, proof against a malicious database
administrator, an authenticated row/root checkpoint or WebAuthn signature proof.
Existing independent trust, signature, source and witness gates remain required.

## Versioning and pending verification

Source revision `.65` and all 20 v9 DDL revision pins identify the current
successor source. The initial four-table correction was revision `.27`. The
operation manifest binds the read contract and table set; the schema source
contract and owner verification profile also bind the configured verifier role
and SHA-256 digest of the exact shared query text. Older recorded contracts and
profiles are not silently accepted or resealed. Receipt-only repair does not
authorize an unrelated privilege/source transition.

Pure/source regressions inspect the actual constructors, call sites, identity
guards and contract bindings without executing extracted code or replacing the
registry. The separate authored native fixture exercises the actual catalog
query on an externally prepared disposable PostgreSQL 16 cluster; its temporary
roles, schema and database-ACL changes are transactional and rolled back. Neither
fixture has run for this source. Historical test IDs are retained while the
native baseline/subcases cover all six relations and denial of the old
four-table installation. The separate source assertion still pins the actual
WebAuthn evidence SQL to its four-table subset. The native fixture remains behind the approved coverage and
changed-excluded-test gate, not a passing exclusion or manual execution waiver.

Still required: actual sealer and runtime/service verification with separately
provisioned identities, valid mTLS, negative privilege drift, recorded-contract
rejection, and signed migration/rollback coverage. Full startup, remaining
WebAuthn kernels, trusted audit initialization and delivery, and production
infrastructure remain incomplete. Follow `goal.md` before any execution.

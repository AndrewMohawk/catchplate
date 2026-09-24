# Planner-writer metadata permissions

Status: source implementation and read-only review only. This tree is unbuilt
and unexecuted. The change does not provision database roles or establish
production readiness.

## One source-owned permission contract

The planner writer persists authorized planning records and reserves execution
envelopes; it is not a general business-data writer. Its existing permission
surface is unchanged: eleven metadata tables and five invoker functions. The
immutable inventory in
[`planner_writer_sql.py`](../serverware/authority_store/planner_writer_sql.py)
now supplies both schema grants and a fixed catalog-admission query. Existing
audit-capacity imports retain their names through aliases to this inventory.

| Tables | Permitted table privileges |
| --- | --- |
| Authorization dependency manifests, fence heads, operation mutation templates, query dependency manifests, authenticated table roots | SELECT |
| Authorization projections, retained plans, WebAuthn assertion evidence | SELECT, INSERT |
| Execution envelopes, planner transactions | SELECT, INSERT, UPDATE |
| Writer capabilities | SELECT, UPDATE |

The five executable functions remain the audit-capacity assertion, domain
digest, and wire JSON/string/walk helpers with their exact argument signatures.
The query checks invoker rights, language, strictness, volatility, exact search
path configuration, function kind and ownership relative to the namespace.
It does not authenticate function bodies or independently enroll their owner.

The pure query builder accepts only two bounded, exact strings: the role and
namespace names. Both are bound parameters. Neither caller-supplied grants nor
identifiers are interpolated into SQL. The eleven-table and five-function
inventories are embedded from source, and the exact query bytes have a SHA-256
digest. Any returned violation denies; no row admits only this catalog contract.

## What sealing now rejects

For a distinct planner-writer role, schema sealing rejects a nonexact table or
function inventory before opening its cursor. After grants and existing owner,
ACL and function checks, it runs the shared query before the verifier check.
The query rejects:

- Missing required tables or functions, wrong relation kinds, and executable
  overloads outside the exact function signatures.
- Missing required or additional effective table privileges, including access
  through views, materialized views or foreign tables in the metadata namespace.
- Explicit writer or PUBLIC column grants, even redundant ones; the contract
  grants whole-table privileges only.
- Grant options, sequence privileges, and PUBLIC schema/relation/function ACLs,
  including PostgreSQL default function ACLs.
- Non-LOGIN or elevated roles, memberships in either direction, schema CREATE,
  missing schema USAGE, and database CREATE or TEMPORARY authority.

Separate audit/recovery and legacy shared-role sealing keep their own policies.
This is a metadata-namespace check, not an all-database sandbox or continuous
monitoring against a privileged administrator.

Source revision `.63`, all nineteen v9 DDL revision pins, the schema source
contract and the owner verification profile bind this change. The latter two
include the configured writer role, exact grant inventory, function signatures
and query digest. Older recorded contracts are not silently accepted.

## Verification and remaining integration

The source fixture checks immutable inventories, the real pure builder, bounded
parameters, digest construction and actual sealer/profile linkage. The native
fixture adds twenty-two authored cases using the real query on an externally
prepared disposable PostgreSQL 16 cluster. Its eleven minimal tables and five
trivial functions exercise catalog metadata, not production DDL or semantics.
Every case rolls back; every changed variant restores a positive baseline.
A SQL exception is a test error, never a successful denial oracle.

The [native inventory](native-postgres-verification.md) retains all prior test
IDs and appends the new suite. Neither fixture has executed for this source.
The suite remains excluded from ordinary verification until its approved native
lane is prepared; the manual target is not a waiver of that gate.

Revision `.59` binds the query into the configured original-byte v4 persistence
owner, alongside PostgreSQL version, fixed role/server-reported TLS identity,
transaction mode and connection-continuity checks. Its immutable configuration
now requires independent writer role/TLS pins as a seventh item, with no old-six
fallback. See [writer connection admission](authority-revocation-writer-connection.md).

Revision `.60` adds the private
[measured writer-configuration factory](authority-revocation-writer-configuration.md).
It does not activate a writer request purpose or replace actual connection admission.

Still required: independently configured admission for the latent legacy writer
routes; authenticated verifier-to-planner-to-writer custody; and real installation,
rollback and service verification. No new public operation, WebAuthn kernel,
transport route or production deployment is activated. Follow
[goal.md](../goal.md) before any build or execution.

# Authority table permission closure

Status: source implementation and source review only. No PostgreSQL instance,
role privileges, migration, runtime connection or prepared test has executed
for this tree. This is not evidence of deployed exposure or a verified runtime
repair. Production and initializer admission remain closed.

## Source defect and scope

The metadata ACL sealer grants ordinary runtime CRUD on metadata tables, then
removes write privileges for a source-owned read-only inventory. Its exact ACL
readback uses that same inventory. Twelve newer authority tables were absent
from it: all ten phase-two primitive tables, plus authorization dependency
manifests and operation mutation templates. Consequently the generated grants
and their readback agreed on ordinary write privileges for those twelve tables.
Checking that agreement did not establish the intended authority boundary.

The ten primitive tables are activation evidence bindings, bounded aggregate
states, continuations, exact pages, external evidence receipts, opaque values,
sealed values, secondary index heads, tombstones and work pages (each with the
`policy_authority_` prefix). Tree-maintenance triggers are not authorization:
they update authenticated leaves and roots after a row write, without checking
an operation capability or independent witness. Direct runtime access to the
global aggregate would therefore be inconsistent with its measured CAS model.
No mutation or exploit reproduction was performed to establish this finding.

## Coordinated correction

`authority_contract.PHASE2_STORE_TABLES` owns the exact sorted ten-table tuple;
the backfill specification references it directly.
`V9_ADDITIONAL_PROTECTED_TABLES` combines those ten with the two contract tables.
These are additional permission/schema dependencies, not an immutable-table
classification: some require legitimate measured updates or maintenance writes.

The complete metadata runtime read-only set now includes all twelve. Existing
sealer revocation and exact readback use this set. The canonical metadata-schema
sealer rejects any caller-supplied read-only set that differs from the exact
source frozenset, before issuing SQL. The recovery-witness and audit schema
sealers keep their separate policies; expected-schema preparation and both
metadata installation/repair call sites still supply the exact shared set.

Detailed schema inventory also includes the twelve tables, so their actual
definitions, constraints, indexes, triggers and table authority participate in
the expected/recorded structural comparison. The existing temporary-shadow
guard consumes that same schema inventory. Previously the all-relation authority
manifest recorded their ACLs, but their detailed table definitions were omitted.

Source revision `.26` and all 17 v9 DDL pins identify the changed contract. The
operation manifest commits both storage tuples; the schema source contract
additionally commits the complete runtime read-only inventory. Prior installed
source/structural contracts are not silently accepted or repaired. A separately
reviewed offline transition remains necessary for an existing installation.

No runtime INSERT template is added for the global counter. Executor direct
business DML remains empty; only its existing SELECT loop expands to include the
newly protected relations. Planner and capability-issuer grants remain unchanged.
The existing runtime policies for credentials, principals, routes and OIDC
sessions are not expanded or frozen by this correction.

## Runtime admission check

The non-admin metadata connection now queries effective privileges for the
complete source read-only set after identity/schema/temporary-shadow admission
and before accepting the recorded owner-function contract. It binds table names
as parameters and resolves each only inside the fixed metadata namespace.

It rejects a missing schema/relation, a non-table/non-partitioned-table object,
missing full-table SELECT, or any effective INSERT, UPDATE, DELETE, TRUNCATE,
REFERENCES or TRIGGER privilege. It separately checks any-column INSERT, UPDATE
and REFERENCES. PostgreSQL's inquiry functions treat comma-separated privileges
as an any-of test; the column inquiry also sees table-level grants. These checks
are therefore not limited to direct table ACL entries. See the
[PostgreSQL 16 privilege inquiry contract](https://www.postgresql.org/docs/16/functions-info.html#FUNCTIONS-INFO-ACCESS-TABLE).

Missing objects and unexpected NULL results fail closed, with a CASE branch
avoiding privilege inquiries on objects of the wrong kind. Existing role
membership restrictions remain in force. The query observes privileges at
connection admission, not continuously after arbitrary privileged DDL changes;
it does not make a malicious database administrator or a substituted database
root trustworthy. The admin/offline path is not subjected to the runtime
read-only check.

## Required execution evidence

The authored fixture imports the real pure source inventories and inspects the
actual sealer, catalog check, call sites and schema/source-hash branches without
importing the blocked database/transition registry. It does not execute extracted
AST code or substitute a mock successful connection. Source linkage is not a
native ACL or startup result.

The controlled PostgreSQL lane must still prove the installed sealer and runtime
admission together: exact SELECT-only grants on all twelve tables, denied direct
DML, missing-table and wrong-kind rejection, column/PUBLIC/inherited privilege
drift rejection, unchanged unrelated roles/tables, exact source and detailed
schema comparisons, old-contract rejection, and legitimate measured executor
writes. Do not manually run a scratch sealer or treat AST assertions as that
evidence. Follow `goal.md` implementation/freeze/preparation/no-build ordering.

The [audit initializer](authority-audit-initialization.md) still needs an
independently accepted database root/cardinality checkpoint and all-writer fence,
exact counter absence and after-root checks, and a purpose-specific durable
installation receipt. This permission repair supplies none of those authorities.

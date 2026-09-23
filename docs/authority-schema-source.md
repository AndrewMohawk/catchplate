# Canonical metadata schema and migration comparison

Status: source implementation and read-only review only. No interpreter, test,
SQL engine, migration, ACL installation or startup has executed for this tree.
This correction is not production admission or permission to repair an existing
database without its exact offline contract.

## Complete source versus extension source

The completed v8-to-v9 retry passed only the v9 table extension to a structural
validator that required the base metadata schema. Receipt repair additionally
required extension-only source equality before calling that same validator.
Neither a complete nor an extension-only input could meet both repair checks.
These were source-level fail-closed errors, not demonstrated live failures.

The declarations now have two no-I/O source constructors and one composer:

- `authority_store.metadata_schema_source.metadata_base_schema_source()` owns
  the unchanged base literal, including the inert retired-table comment.
- `authority_store.v9_schema_source.authority_v9_schema_source()` owns the
  unchanged v9 function and its two source-owned final-budget substitutions.
- `metadata_schema_source()` concatenates those exact results. It accepts no
  external SQL, paths, configuration or replacement arguments.

At the schema-source extraction checkpoint, the base literal and extension
function were preserved byte-for-byte at source revision `.26`. The subsequent
[verifier-read correction](authority-verifier-read-permissions.md) advances the
current revision to `.27` and updates its 17 v9 revision pins. The executor
retains its existing extension API by directly importing the sole constructor.
The containing package still imports the schema facade and its dependencies;
these are no-I/O source constructors, not a claim of a standard-library-only
package import or an executable full startup.

Bootstrap, completed retry and receipt repair now use the complete program for
comparison. Fresh v8-to-v9 migration still executes only the extension over its
locked existing v8 state. It never replays the complete base DDL as a repair.

## Exact comparison and receipt-only replacement

`completed_v9_schema_source.require_metadata_schema_program` admits only an
exact string equal to the canonical complete program. The expected-schema
engine calls it before SQL, savepoints or SQLite construction. Sentinel names
alone no longer admit a caller-supplied schema program.

The only other comparison shape is the explicitly selected historical receipt
declaration. Its pure constructor first requires the canonical complete target,
then replaces exactly one receipt-table span between unique ordered source
boundaries. The base schema and every nonreceipt byte remain unchanged. The
legacy flag is an exact boolean and only the dedicated repair comparison opts
in. Extension-only, truncated, reordered, duplicated, altered or unrelated
historical schemas are rejected.

The receipt table stays in structural, immutable and ACL inventories. The
migration's separate population commitment excludes terminal-custody rows
(schema contract, owner contract and receipt) to avoid recursive receipt
commitments; this is not a structural exclusion.

## Fresh migration must validate before signing

After its existing authorized extension and guard installation, fresh migration
now applies the exact bootstrap role/ACL sealer. It compares live structure
against the complete source before capturing the signed after-manifest or
requesting a signature. The returned validated structural JSON and digest are
the values recorded in the schema and owner contracts; observed structure alone
is no longer promoted to expected structure.

After receipt and owner/schema records are inserted, the same transaction checks
the exact recorded contracts against complete source before returning a terminal
result. Any failure rolls back the transaction. Existing signature, row-change,
version, ownership and replay checks are retained. Ancillary v8 outbox/RBAC/
storage-epoch objects must already satisfy their source comparison or fail
closed; this change does not silently overwrite unrelated legacy definitions.

## Ownership is the configured authority role, not the session login

ACL sealing assigns namespace and object ownership to the configured authority
NOLOGIN role. Structural capture previously compared those owners to
`current_user`, incorrectly requiring the separate bootstrap login to be the
semantic owner after sealing.

Capture now checks the exact configured owner name, a positive 32-bit OID, and
literal false values for LOGIN, SUPERUSER, CREATEROLE, CREATEDB, REPLICATION and
BYPASSRLS. Missing or NULL values fail closed. Relation and function ownership
queries bind the accepted OID and require literal true equality before ACLs are
normalized to the existing `schema-owner` label. No session role, grant,
membership policy or ACL normalization is changed. Existing independent
role-membership and owner-function admission remain required.

The schema source contract now commits the complete UTF-8 schema program under
`serverware.metadataSchemaProgram/v1`, the configured owner name, and ownership
contract `serverware.policyAuthorityObjectOwnership/v1`. An older recorded source
digest is intentionally not accepted just because its SQL revision is `.26`.
Receipt-only repair does not authorize unrelated source/owner-contract upgrades.

## Evidence still required

The authored regression fixture calls real pure source constructors and checks
the production call sites and ordering with bounded source inspection. Existing
primary-key, audit-capacity and trust-projection fixtures consume the same moved
declarations. These tests are unexecuted and do not prove PostgreSQL syntax,
locking, transaction rollback, ownership, ACLs or a successful signed migration.

The controlled PostgreSQL lane still needs actual pristine bootstrap, fresh
v8-to-v9 migration, exact completed retry, eligible receipt-only repair, distinct
bootstrap/owner identities, owner/role drift rejection, unrelated schema drift
rejection, signature/CAS failures, rollback and scratch-schema cleanup. The
changed native trust-projection fixture remains subject to the approved coverage
baseline and changed-excluded-test gate; the new pure fixture is not a waiver.

New source modules must enter the exact tracked/frozen source and import-tree
closures. Prior artifacts and manifests cannot verify this tree. Follow
`goal.md` before any preparation or execution. Independent audit initialization,
root/cardinality authority and all-writer fencing remain separate missing work;
see [audit initialization](authority-audit-initialization.md).

# Catalog admission under restricted PostgreSQL roles

This is source-only implementation: unbuilt, unexecuted and not independently
release-verified. No PostgreSQL roles, privileges, tables or services were changed.

## Required reader scope

The commit reader requires the same eight-field profile as protected custody:
DSN, timeout, fixed role, TLS client DN/serial/issuer DN, source query-manifest
digest and independently expected structural-manifest digest. Missing the last
pin is an error; there is no seven-field compatibility or observed-digest fallback.
Its actual owner is bound to its creating process.

The cold completion bootstrap supplies both readers' catalog pins from the
same root-signed `structureManifestDigest`. The recovery composition checks
both query and catalog pin equality, without comparing deliberately distinct
role/TLS connection strings or pretending equality proves database identity.

On each actual read-only physical connection, the complete source catalog
producer and digest are checked before and after marker/vector observation.
The fixed search path, role/TLS/privilege checks, original work/window, inherited
deadline and normal closed-handle return remain required. The expected pin is
independently generated and admitted, never taken from the observed database.
Before/after checks operate inside the existing transaction; they are not a
continuous DDL lock or proof of catalog stability after the transaction ends.

## Role-independent column metadata

The old column query used `information_schema.columns`. PostgreSQL filters that
view by ownership or column privileges, so a reader with access only to marker
and root tables cannot use it to describe the entire source schema. This is
visible in PostgreSQL 16's [view definition](https://github.com/postgres/postgres/blob/REL_16_STABLE/src/backend/catalog/information_schema.sql#L624-L734).

The shared schema producer now uses a fixed, parameterized
[`pg_catalog` query](../serverware/authority_store/postgres_column_manifest.py)
for those column fields. It reads system metadata, not business rows, and does
not widen the reader's relation privileges or change roles. Source table owner,
ACL, constraint, index, trigger, function and namespace checks are retained.

The projection preserves the existing six manifest values: name, displayed
type, underlying type name, nullability, default and ordinal. It handles domains,
array labels, noncatalog types, domain NOT NULL, generated-column defaults and
dropped-column exclusion. The expected-schema producer uses the same path.
Runtime equivalence and complete equal manifests across roles are not claimed
until the frozen PostgreSQL verification below succeeds.

## Deferred verification

The consolidated frozen suite must cover required pin/type/PID rejection,
actual catalog mismatch before and after readback, unchanged read-only ACLs,
physical-connection substitution, normal and late-error closure, and original
deadline exhaustion. It must compare installer and restricted-role manifests
on the real PostgreSQL 16 schema, including hidden business-table columns.
Projection cases include built-in types, domains, arrays, user-defined types,
NOT NULL/default behavior, generated columns and dropped attributes. No fixture
or owner-privileged run alone proves restricted-role behavior.

Metadata reads and native driver work still need bounded production execution;
cooperative deadline checks are not hard syscall cancellation. A catalog match
does not establish database provenance, hostile-host integrity, deployment
currentness, release custody or authorization to execute or finalize anything.

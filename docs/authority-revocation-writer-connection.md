# Configured revocation writer connection

Status: source implementation and read-only review only. No build, interpreter,
test, database, service or TLS verification has executed for this tree.

## Independent configuration

`RevocationPlannerPersistence` now requires a seventh immutable configuration
item: `(databaseRole, tlsClientDn, tlsClientSerial, tlsIssuerDn)`. The role is
exactly `serverware_policy_authority_planner_writer`. Each TLS pin is an exact,
nonempty, NUL-free string within 4,096 UTF-8 bytes. Neither a retained signed
plan nor a successful connection supplies these expectations. Existing public
keys remain at indices two/three and signing identities at four/five.

The old six-item configuration is rejected. There is no default TLS identity,
per-call pin override or compatibility bypass. Connection timeout is an integer
from two through 300 seconds. The held DSN is bounded to 65,536 UTF-8 bytes and
rejects NUL and line breaks. This local scalar validation is not independent
database, CA, credential or measured-service enrollment.

The owner captures all fifteen external verification expectations on the
caller's existing work before opening a socket. The genuine DB facade import
gate remains before connection creation. The shared connector used by the
independent issuer is unchanged.

## Owning transaction and admission

The new private connection owner opens no additional socket and owns the exact
handle returned by the configured connector, with autocommit explicitly off.
Before calling any custody store it requires:

1. The original physical connection, initially idle, and exact context handles.
2. A real outer transaction in the active state, with the first application SQL
   setting `SERIALIZABLE READ WRITE NOT DEFERRABLE`.
3. An exact nineteen-field identity row: PostgreSQL 16, current and session role
   equal to the fixed configured writer, SSL and LOGIN literally true, matching
   server-reported client DN/serial/issuer, and literal-false elevated/DDL flags.
4. No violation from the actual shared
   [planner-writer privilege query](authority-planner-writer-permissions.md).

These observations do not replace trusted DSN/CA configuration or authenticate
a malicious PostgreSQL administrator. Catalog admission is not continuous
privilege monitoring, authenticated root currentness or function-body proof.

Narrow connection/cursor/result wrappers retain the original physical handle,
active transaction and shared work around driver property/method lookups,
SQL/fetch calls and row-count access. The actual DB facade and genuine store
functions remain in use. Their existing role/mode gates and nested savepoints
are not skipped; the same work pays for real signature and proof replay.
This narrow adapter supports those stores' entered-cursor calls; it is not a
general replacement for every method on the database facade.
Admission/driver metadata remains outside H/B/N rather than consuming a new
allowance. No successful-verification object is accepted as input.

The result is returned only after the writer transaction and connection scopes
exit. Failed work or identity checks still attempt cleanup on original handles;
cleanup cannot suppress the first failure. Status/handle continuity cannot
detect a hostile driver that secretly commits and begins again. A post-exit
failure is potentially indeterminate: it cannot undo a completed commit.

## Scope that remains unfinished

This checkpoint covers the independently configured private v4 persist, retained
read and execution-reservation owner. It does not add a public service route or
construct that owner from measured service configuration yet. It also does not
combine separate `persist` and `reserve_execution` calls into one transaction.

The legacy service still registers `persist-measured-plan`,
`read-persisted-plan` and `reserve-execution-envelope`. Their current import path
is blocked by incomplete registry closure, but they are latent executable
routes, not retired handlers. Their writer connectors still need independent
TLS pins and equivalent admission before any future activation. The legacy
verifier's direct reservation call also conflicts with the planner-only writer
peer topology; widening peers is not an accepted repair.

The successor still needs authenticated verifier authorization relayed through
the planner, durable original-byte retries, writer response-key custody, an
explicit whole-message size contract, atomic retain-plus-reserve and actual
runtime/rollback evidence. Production Nitro/KMS, signing and independent witness
services remain unprovisioned. Source fixtures and synthetic driver observations
are not real PG16, ACL, TLS, transaction durability or deployment evidence.
Follow [goal.md](../goal.md) before any execution.

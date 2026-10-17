# Activation execution SQL bootstrap

This source-only profile admits the dedicated SQL receiver for
`oidc.session.activate`. It does not relabel a registration worker or accept
the planner bootstrap as SQL authorization. The role launch and external
[receiving-custody original](oidc-session-activation-execution-custody-bootstrap.md)
are separately root-signed; the latter must genuinely admit consumer
`sql-issuer` and its embedded original planner bootstrap. No resource, key,
account, current checkpoint or production authority is provisioned here.

## Closed role and original admission

The exact matching schemas are
`catchplate.signedOidcSessionActivationExecutionSqlBootstrap/v1`,
`catchplate.oidcSessionActivationExecutionSqlBootstrap/v1` and
`catchplate.oidcSessionActivationExecutionSqlLaunch/v1`. The envelope schema is
the distinct root-signature domain. The canonical role original is capped at
4 MiB and the separate receiving original at 8 MiB; its signed `receivingCustody`
record contains only `byteCount` and the original-byte `bytesDigest`.

The role authenticates its independent `receiverIdentity`, configuration,
generation and runtime-closure digests, database identity, three original
current-root/grant/activation-caller enrollments, predecessor and current
pending scope, attempt checkpoint, database/TLS configuration and original
launch interval. Each enrollment is an exact base64url/byte-count/raw-digest/
framed-identity record. Whole original inventory remains under the existing
64 MiB ceiling before nested admission callbacks.

Actual receiving admission replays the embedded planner original. The SQL
role joins its receiver identity and configuration/generation/runtime pins to
that genuine result, and byte-compares its current-root enrollment with the
planner's admitted original. Actual activation caller, current-root and grant
verifiers run on the same work. Caller purpose, grant audience, configured
planner SPKI and actual operation-root SPKI remain mandatory; generic roles or
WebAuthn evidence-purpose keys are not substitutes. The caller key is also
separated from configured role and optional enrollment/evidence/transition
keys, and UID/GID `65504` cannot reuse a configured generic role identity.

There is no computation, grant-authorizer or completion private key in this SQL
profile. Its receiver identity joins the two original root statements, not a
computation measurement. These are trusted-host-local claims, not measured
runtime. `hardwareBacked`, `nativeStageZero`, `hsmBackedKeys`, `teeVerified`
and `externalWitnessVerified` must all be exactly false.

## Independent state and attempt pins

| Signed field | Exact scope and checks |
| --- | --- |
| `statePredecessor` | `sequence`, `headDigest`, `nextFence`; genesis requires the actual enrollment digest and fence one |
| `currentPending` | Independently supplied `sequence`, `headDigest`, `fence`; sequence must equal predecessor sequence plus one and fence must equal its next fence |
| `attemptCheckpoint` | Independent local `sequence`, `headDigest`; sequence zero must equal the actual source/catalog-bound attempt genesis |

The pending head is never copied from a reservation acknowledgment, local
journal, SQL response or historical receipt. Coherence between independently
supplied numbers is not evidence of currentness. A valid static root statement
does not observe a live owner or make later issuance atomic; genuine pending
original verification and protected issuer/executor checks remain required.

Pending sequence must leave completion capacity below the enrolled maximum.
The attempt journal's independently signed maximum is between two and the
source maximum, cannot exceed enrolled capacity, and must contain the supplied
attempt sequence. It need not equal the state journal's maximum. The actual
`attempts._genesis_on_work(structureManifestDigest, work)` binds both the current
source revision and catalog pin. No local scan selects a checkpoint. This
profile has neither a reservation checkpoint nor a state-transport endpoint.

## Fixed database and TLS configuration

`databaseEndpoint` is exactly `host`, `hostaddr`, `port`, `databaseName`. The
source validates bounded canonical server-name/address/database scalars and
constructs both DSNs itself. No caller-supplied DSN, connection URI, list,
service name or password is accepted. Both roles use the same literal address,
port, database and verified server name. This root-asserted same-database
provenance must be established independently; matching digests or endpoints
alone do not prove it.

`sqlRoles` has exactly `issuer` and `executor`, each with
`connectTimeoutSeconds`, `clientDn`, `clientSerial`, `issuerDn`. The resulting
actual eight-tuples are `(dsn, timeout, fixed_role, client_dn, client_serial,
issuer_dn, query_manifest_digest, structure_manifest_digest)`. Roles are fixed
to `SUCCESSOR_ISSUER_ROLE` and `SUCCESSOR_EXECUTOR_ROLE`. The query digest joins
the genuinely admitted configuration; the structure pin is independently
root-supplied, never learned from the database. Actual protected owners must
check their real catalog under the same physical connection.

Every generated DSN requires `sslmode=verify-full`, `passfile=/dev/null` and
`gssencmode=disable`. Fixed TLS paths are under
`/run/catchplate/oidc-session-activation-execution-sql-tls/`:

| Logical TLS original | Fixed filename | Byte ceiling |
| --- | --- | --- |
| `ca` | `ca.pem` | 64 KiB |
| `issuerCertificate` | `issuer.crt` | 64 KiB |
| `issuerKey` | `issuer.key` | 16 KiB |
| `executorCertificate` | `executor.crt` | 64 KiB |
| `executorKey` | `executor.key` | 16 KiB |

Each `tlsFiles` record is exactly `byteCount` and `bytesDigest`, minimum two
bytes. This verifier reads no TLS file. The fixed delivery/startup must join
these pins to protected originals and exclude `PG*`, password, service-file
and home-directory environment fallback. Independently provisioned
certificate-only PostgreSQL authentication remains necessary.

## Fixed launch and private API

The process is `oidc-session-activation-execution-sql`, UID/GID `65504`, with
request peer `65532:65532`. The listener is
`/run/catchplate/oidc-session-activation-execution/sql.sock`; both its kernel
socket and pathname device/inode are signed. The fixed journal is
`/var/lib/catchplate/oidc-session-activation-execution-sql-attempts`, with signed
directory device/inode and `journalMaximumRecords`. Request timeout is integer
1–30 seconds. Device values allow zero; inodes are positive UInt64 values.

The exact seven inherited FDs are root198, bootstrap199, listener200,
receiving-custody201, bundle AES202, delivery AES203 and attempt journal204.
There is no `signingKeyFd`. The two raw AES keys are never serialized in the
role; genuine receiving/planner originals separately pin them and enforce
their separation from each other and the planner journal key.

`_verify_on_work(*, bootstrap_bytes, custody_bytes, root_public_key, work,
live_window=None, transport_deadline_ns=None)` admits the actual originals.
`_produce_on_work(*, payload, custody_bytes, root_private_key, root_public_key,
work, live_window=None, transport_deadline_ns=None)` owns the closed input graph,
performs the same genuine joins and signs only independently established
claims. `_fresh(interval, work, opening=None)` preserves the original bracket.

Returned `_SqlMaterial` is private ordinary same-call data: original role and
receiving bytes/material, independent receiver identity, admitted configuration
and enrollment originals, actual planner and operation-root public keys,
database/generation/runtime scope, caller age/skew, predecessor/current-pending/
attempt tuples, both actual connection eight-tuples, TLS pins and original
launch clocks/resources. It is not a reusable admission capability, and no
public verifier accepts it instead of originals.

An optional supplied live window and inherited absolute deadline remain binding
through all nested verification, signing and final return. The role interval
must fit the original receiving interval, which fits the planner interval;
all are capped at 300 seconds and rechecked against their original openings.
No new work allowance or renewed interval is created.

This module opens no database, key, journal, socket or TLS file. It establishes
neither SQL completion nor token release, session activation, historical
recovery or independent action-time currentness. Source implementation and
declaration joins are unbuilt and unexecuted, not production acceptance.

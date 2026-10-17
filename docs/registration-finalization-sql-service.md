# Cold finalization SQL worker contract

The dedicated `registration-finalization-sql` profile admits only the fixed
`webauthn.registration.finalize` purpose. Its [root-signed bootstrap](../catchplate/registration_finalization_sql_bootstrap.py)
binds the original configuration, purpose enrollments, current pending scope,
attempt-journal checkpoint and two restricted database TLS identities before
the worker can select resources. This is source-only, unbuilt, unexecuted and
unprovisioned; no account, key, database privilege, service or production gate
is supplied by a bootstrap signature.

## Fixed resources

| Resource | Source-fixed value |
| --- | --- |
| Process mode and role | `registration-finalization-sql` |
| Worker UID/GID | `65509:65509`, no supplementary groups |
| Request peer | `65532:65532` |
| Root/bootstrap/listener/journal descriptors | `198`, `199`, `200`, `201` |
| Listener | `/run/catchplate/registration-finalization/sql.sock` |
| TLS directory | `/run/catchplate/registration-finalization-sql-tls` |
| Authority signing keys | None |

The bootstrap uses separate schema/domain
`catchplate.signedRegistrationFinalizationSqlBootstrap/v1`, payload
`catchplate.registrationFinalizationSqlBootstrap/v1`, and launch
`catchplate.registrationFinalizationSqlLaunch/v1`. Evidence-worker originals
are not a fallback for these closed finalization schemas.

The exact launch fields bind process mode, service/peer identities, the four
descriptor numbers and ordered inherited descriptor inventory, listener path,
listener-FD/path device/inode identities, journal-directory device/inode,
`journalMaximumRecords` and integer `requestTimeoutSeconds` in `1..30`.
There is no signing-key descriptor or caller-chosen path.

## Genuine purpose and independently supplied state

The payload contains complete `configurationPayload`, `configurationDigest`,
`generation`, `runtimeRoleIdentities`, `databaseId`, `generationDigest` and
`runtimeClosureDigest`. Actual finalization transition configuration admission
supplies the planner key and operation key; the evidence-admission mapper is
not invoked as authority. The runtime-closure pin remains an independently
established root assertion, not a measurement performed by this module.

`currentRootEnrollment`, `grantEnrollment` and `authorizationEnrollment` each
hold exactly `base64Url`, `byteCount`, `bytesDigest` and `identityDigest` for the
original enrollment. Real root/current-root/grant/finalization-caller admission
joins their byte identities, database/generation and key scopes. The dedicated
caller key must remain disjoint from the actual enrolled and configured
purposes, including enabled enrollment, evidence and transition keys. Only its
public enrollment is present; no caller/grant/computation/completion/state
private signing key belongs to this SQL worker.

The root independently supplies:

- `currentPending`: exact `sequence`, `headDigest`, `fence`. Sequence is positive
  and strictly below the current-root enrollment's `maxRecords`, leaving
  completion capacity. No acknowledgment or scan fills these expected pins.
- `attemptCheckpoint`: exact `sequence`, `headDigest`. Sequence must not exceed
  the separately signed journal maximum; that maximum is `2..1024` and cannot
  exceed enrolled capacity. At sequence zero, the head must equal the genuine
  source/catalog-bound attempt-journal genesis.
- `queryManifestDigest`, joined to the actual configuration, and independently
  pinned `structureManifestDigest`, used by both actual SQL owners and the
  attempt-journal genesis.

A signed pending head is not evidence that it remains current at action time.
Independent current authority, real database comparisons and storage
continuity remain necessary; neither a response nor a restart advances the
bootstrap's expected pending scope or local checkpoint.

## Closed database and TLS configuration

`databaseEndpoint` is exactly `host`, `hostaddr`, `port`, `databaseName`. The
literal address must be canonical concrete unicast; the server name is
canonical lowercase DNS or a canonical literal address. Port is `1..65535`;
the database name uses the source's closed ASCII identifier profile. There is
no DNS endpoint selection, address list, arbitrary DSN or connection URL input.

`sqlRoles` contains exactly `issuer` and `executor`. Each has
`connectTimeoutSeconds` (`2..300`), `clientDn`, `clientSerial`, `issuerDn`
(bounded exact text). The source constructs separate DSNs with the fixed
`SUCCESSOR_ISSUER_ROLE` and `SUCCESSOR_EXECUTOR_ROLE`, the same exact endpoint
and database name, `sslmode=verify-full`, `passfile=/dev/null` and
`gssencmode=disable`. Configured connect timeouts cannot renew the enclosing
request or original launch deadline.

`tlsFiles` has exactly five logical fields, each containing only `byteCount`
and `bytesDigest`:

| Field | Fixed basename | Byte bounds |
| --- | --- | --- |
| `ca` | `ca.pem` | `2..65536` |
| `issuerCertificate` | `issuer.crt` | `2..65536` |
| `issuerKey` | `issuer.key` | `2..16384` |
| `executorCertificate` | `executor.crt` | `2..65536` |
| `executorKey` | `executor.key` | `2..16384` |

The bootstrap reads none of these files. Protected fixed-file delivery must
verify their exact originals after root admission; the cold environment must
exclude `PG*`, service-file, password and other libpq fallback settings.
Certificate-only PostgreSQL authentication and role grants are separately
provisioned. Matching endpoint fields or signed hashes do not prove that both
credentials reach the same genuine database.

## Original lifetime and implementation boundary

Bootstrap originals are bounded to 4 MiB and a positive interval of at most
300 seconds. `trustMode` is `trusted-host-local`; `hardwareBacked`,
`nativeStageZero`, `hsmBackedKeys`, `teeVerified` and `externalWitnessVerified`
are all false. `_verify_on_work` and `_produce_on_work` use the supplied work;
`_fresh(interval, work, opening=...)` preserves the original epoch/monotonic
opening without renewal.

The private `_SqlMaterial` retains the owned configuration/generation/runtime,
three enrollment originals, planner and `operation_public_key`, enrolled
database/generation identities, runtime pin, pending/checkpoint tuples,
`issuer_configuration` and `executor_configuration` exact eight-tuples,
`tls_files`, original interval/opening and launch. These are ordinary same-call
data, never an accepted successful-admission token. The eighth SQL tuple field
is the required catalog pin; no seven-field fallback exists.

The [entrypoint](../catchplate/registration_finalization_sql_entrypoint.py)
owns protected delivery; the dedicated startup retains one accepted connection,
one pre-body work/window and an inherited absolute deadline. Invalid peers or
frames do not authorize another attempt. The [actual SQL composition](registration-finalization-sql.md)
still performs genuine original admission, protected issuance, durable attempt
claim and execution through the real owners. Bootstrap verification itself
opens no database/journal/listener and performs none of those effects.

Independent provisioning, immutable source/runtime closure and frozen
verification remain outstanding. Observed SQL commit is not completion,
latest-head authority, public caller permission or separate OIDC browser-session
activation; no failure grants an automatic retry.

## Cold process and one request

The [isolated launcher](../catchplate/registration_finalization_sql_launcher.py),
[startup owner](../catchplate/registration_finalization_sql_startup.py) and
[runner](../catchplate/registration_finalization_sql_runner.py) retain the fixed
process identity, literal environment, sealed descriptors, protected TLS paths
and actual attempt-journal/SQL owners. The sole request work allowance and
live window open **before peer, frame or body reading**. Its `1..30` second
deadline is clipped to the original cold-launch deadline; the same window,
work and absolute bound cover reading, admission, SQL and response handling,
without renewal.

At most one accepted connection is handled per launch, including an invalid
peer or malformed frame. After the exact raw13 is read, an irreversible
in-process spent latch is set before SQL composition. Idle waits do not spend
the launch; an accepted exchange never triggers another connection or retry.

The raw4 response is an unsigned local observation. `observed-commit` carries
the actual issued locators and marker, not signed completion or independently
current authority. Ordinary failures yield `uncertain`: only the typed
post-issuance error may retain the actual issued IDs; other failures carry no
IDs, and neither case carries a marker or exception text. Cancellation and
terminal lifecycle failures are not converted into a verified outcome; a
missing response does not establish noncommit or permit retry.

The [private caller](control-plane-finalization-sql.md) remains distinct from
public activation. The [socket](../ops/systemd/catchplate-registration-finalization-sql.socket)
and [service template](../ops/systemd/catchplate-registration-finalization-sql.service.in)
are uninstalled source packaging, with no automatic process restart or
provisioning supplied by these files.

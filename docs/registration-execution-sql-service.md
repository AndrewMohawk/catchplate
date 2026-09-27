# Cold registration SQL service

This source-only, trusted-host-local service supplies the cold owner for the
[registration SQL bridge](registration-execution-sql.md). Its one fixed operation
is `webauthn.registration.evidence.admit`. It authenticates original controls
and invokes the actual protected issuer and one-use executor; it does not
finalize a credential, sign a completion or activate a session.

The source and packaging are unbuilt, unexecuted and uninstalled. No public
caller is connected to this service. Existing public reserve routes remain
reservation-only. **0 of 6 production acceptance gates are verified.**

## Independent cold inputs

The independently signed bootstrap binds the actual configuration, generation,
runtime role identities and original caller/grant/current-root enrollments. It
also binds two different checkpoints:

- `currentPending`: the expected current pending sequence, head digest and
  fence for SQL admission. These are never copied from the submitted state
  acknowledgment.
- `attemptCheckpoint`: the independently held sequence/head for the separate
  durable executor attempt journal. It is not a reservation journal or the
  control-plane grant's local ID.

The closed schemas are `serverware.signedRegistrationExecutionSqlBootstrap/v1`,
`serverware.registrationExecutionSqlBootstrap/v1` and
`serverware.registrationExecutionSqlLaunch/v1`. The original bootstrap is
bounded to 4 MiB. Its `_verify_on_work` authenticates root originals before cold
resource selection; `_produce_on_work` signs independently established claims,
not evidence of their provenance or currentness.

The root signature authenticates the supplied pending-state claim; it is not a
live witness that the pending head remains current. Independent currentness
and actual protected database admission remain necessary. The launch does not
advance either checkpoint from incoming responses or scan a journal to invent
its own trusted recovery head.

Real issuer/executor PostgreSQL configurations have separate fixed database
roles and independently admitted per-role TLS identities. Independent query
and catalog pins, privileges and same-database provenance must be supplied;
matching query/catalog pins alone cannot establish that distinct connections
reach the intended database. No submitted DSN, SQL statement, operation selector
or successful-inspection token replaces those cold inputs.

The bootstrap fixes one database endpoint: canonical DNS/IP verification name,
concrete canonical unicast `hostaddr`, port and bounded database name. TLS uses
`verify-full`; the source fixes `passfile=/dev/null` and `gssencmode=disable`.
Role connection timeouts remain clipped to the original request/lifetime.

The launch is bounded to at most 300 seconds, with a request timeout of
1–30 seconds. One original cold launch accepts **at most one connection** and
exits, including after an ordinary failure. A malformed or unauthorized
connection terminates without SQL; a valid raw13 consumes the in-process spent
latch before composition. This sacrifices availability for a bounded launch:
there is no reconnect, automatic retry, second request or renewed authorization
window.

## Process, descriptors and TLS originals

The service runs as UID/GID `65512:65512`, without supplementary groups, and
admits the control-plane peer `65532:65532`. The root-created listener is
`/run/serverware/registration-execution/sql.sock`, with pathname ownership
`65512:65532` and mode `0660`. Client-side `SO_PEERCRED` expects the actual
root-activated listener owner `0:0`, not the dropped service identity.

Root delivery retains exactly four fixed descriptors:

| FD | Original owner input |
| --- | --- |
| 198 | Root public key from `/run/serverware/registration-sql-trust/root-public-key.pem` |
| 199 | Signed `/run/serverware/registration-sql-trust/bootstrap.json` |
| 200 | Actual activated listener |
| 201 | `/var/lib/serverware/registration-sql-attempts` directory, `65512:65512`, mode `0700` |

The child uses an exact cleared environment, checked at admission and lifecycle
boundaries; ambient libpq variables are not accepted as connection authority.
There is **no signing-key descriptor**. PostgreSQL client keys are separate
fixed TLS originals, not completion or enrollment authority keys. All five
files below `/run/serverware/registration-sql-tls` are root-owned and bound by
the bootstrap's hashes and byte limits:

| Files | Mode and bound per file |
| --- | --- |
| `ca.pem`, `issuer.crt`, `executor.crt` | `0444`, 2 bytes–64 KiB |
| `issuer.key`, `executor.key` | `0440`, group `65512`, 2 bytes–16 KiB |

Root delivery and cold startup hash the signed fixed originals. Ongoing
continuity checks compare their exact pathname/file metadata identities; they
do not repeatedly hash each file. This is a trusted-host-local continuity
boundary, not hardware key custody, whole-host isolation or a live revocation
check. No key or credential is returned on the wire.

## Fixed raw13 request and raw4 outcome

[`authority_registration_execution_sql_transport.py`](../serverware/authority_registration_execution_sql_transport.py)
uses request magic `SWRSQL01` and response magic `SWRSLR01`. Each frame has an
eight-byte magic, one big-endian u64 byte length for each body, then the bodies
in order, followed by exact EOF. The client half-closes after its request.

The request is grant raw10 followed by reservation raw3:

1. Caller authorization, signed planning request3, signed planning response4,
   complete before-vector and signed grant.
2. Signed reserve request, computation snapshot and signed state acknowledgment.

The combined body ceiling is 64 MiB. Existing individual and planning-group
ceilings are checked before body allocation; adding the reservation originals
does not enlarge the earlier aggregate allowance. The endpoint is exactly
`(sql.sock's fixed absolute path, timeout 1–30 seconds, 0, 0)`.
One inherited absolute deadline covers connect, peer checks, all framing,
half-close and EOF. There are no parsers, callbacks, work allowances, retries
or fallback endpoints in this transport.

The response has exactly four bodies: state, pending-decision ID bytes,
execution-packet ID bytes and marker bytes. Its body ceiling is 4,253 bytes.

| State | IDs | Marker |
| --- | --- | --- |
| `observed-commit` | Both canonical ASCII `sha256:` IDs, 71 bytes each | Actual bounded marker, 2–4096 bytes |
| `uncertain` | Both empty, or both canonical 71-byte IDs | Empty |

No exception text is serialized. IDs are supplied only after actual successful
issuance and are not the control-plane grant ID. The transport validates the
closed shape, not the marker's business meaning or a signed completion.
`observed-commit` is the service's local observation of the actual executor
result, not finalization or a transferable execution permission. An uncertain
outcome establishes neither absence nor rollback; no automatic retry follows.

## Actual execution and recovery boundary

The service passes original raw10/raw3 and independent cold scope to the
existing SQL bridge. Caller/grant controls are authenticated first; the actual
issuer performs the full generic semantic, plan, pending-reservation and grant
replay. The executor receives only this same call's actual custody IDs, using
the original work/window clipped to any shorter issued expiry. Its separate
durable attempt is recorded before executor database work and is never cleared
because a response is missing.

Issuance or execution may have durable effects before failure or disconnection.
The service cannot turn uncertainty into a second issuance/execution attempt.
Genuine protected reconciliation remains necessary; signed completion still
belongs to the separate UID65515 owner, key, journal and protected readers.
Credential finalization must separately authenticate committed evidence and the
retained original signer exchange. Neither path is activated by this service.

Present-caller execution-purpose admission is still required before a future
public caller invokes this private service. Possessing preparation, grant or
reservation originals is not a new public execute permission.

## Source packaging, not deployment

The source chain is the
[`bootstrap`](../serverware/registration_execution_sql_bootstrap.py),
[`root entrypoint`](../serverware/registration_execution_sql_entrypoint.py),
[`startup owner`](../serverware/registration_execution_sql_startup.py),
[`runner`](../serverware/registration_execution_sql_runner.py) and
[`fixed launcher`](../serverware/registration_execution_sql_launcher.py).
The runner uses `initialize_from_environment()`, `require_started()` and
`close()`. The actual owner's `serve_once()` returns `False` only while idle,
`True` after its one completed connection, and any exception ends the launch.
[`Dockerfile.production`](../Dockerfile.production) copies the launcher and the
uninstalled [socket](../ops/systemd/serverware-registration-execution-sql.socket)
and [service template](../ops/systemd/serverware-registration-execution-sql.service.in);
it does not switch an entrypoint or activate a unit.

The template requires reviewed literal substitutions for `SQL_RELEASE_ROOT`,
`SQL_TRUST_DIR`, `SQL_TLS_DIR` and `SQL_JOURNAL_DIR`. It creates no accounts,
database roles, trust/key originals, journal or current-state authority.
`Restart=no` and the one-start limit prevent automatic service restart; fresh
cold admission and independently current checkpoints are not inferred from a
previous process's exit. PostgreSQL access needs AF_INET/AF_INET6 in addition to
the Unix listener; independently restricted database egress is a provisioning
requirement, not a permission supplied by this template.

Read-only mounts do not establish credential provenance or pathname access.
Systemd runtime limits, cooperative termination and cgroup kill escalation are
not hard kernel syscall watchdogs or evidence that a database effect was
rolled back. No Compose wiring, installation, public activation or production
acceptance is included.

## Deferred frozen verification

After source freeze and prerequisite admission, the consolidated verification
must cover:

- Root, pathname, descriptor and environment rejection before resource use.
- A genuine original SQL exchange with the one-connection/one-use boundary.
- Tampered raw13 originals, individual/group/aggregate bounds and wrong peers.
- Durable attempts across errors and an independently admitted cold restart,
  without resetting the journal checkpoint or retrying execution.
- Exact observed/uncertain outcomes, late expiry and absence of automatic retry.

This is planned coverage only; no tests or runtime verification have run for
this source batch.

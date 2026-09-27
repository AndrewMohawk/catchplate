# Consume SQL receiver bootstrap prerequisites

[`oidc_session_activation_delivery_execution_sql_bootstrap.py`](../serverware/oidc_session_activation_delivery_execution_sql_bootstrap.py)
authenticates a distinct root-signed resource contract for the consume SQL
worker. The separate [OS delivery](oidc-session-activation-delivery-execution-sql-delivery.md),
[cold service](oidc-session-activation-delivery-execution-sql-service.md) and
[issuer/executor bridge](oidc-session-activation-delivery-sql.md) connect that
contract to genuine pending admission and protected SQL. This bootstrap alone
does not construct a worker or execute SQL. Source is unbuilt, unexecuted,
uninstalled and unprovisioned; no production acceptance is claimed.

## Fixed role and originals

The closed envelope/payload/launch schemas are
`serverware.signedOidcSessionActivationDeliveryExecutionSqlBootstrap/v1`,
`serverware.oidcSessionActivationDeliveryExecutionSqlBootstrap/v1` and
`serverware.oidcSessionActivationDeliveryExecutionSqlLaunch/v1`. The role is
`oidc-session-activation-delivery-execution-sql`, fixed UID/GID **65498**, with
private peer **65532**. No signing-key field or descriptor exists.

`_verify_on_work` takes keyword-only `bootstrap_bytes`, `custody_bytes`,
`planner_bootstrap_bytes`, `planner_history_custody_bytes`,
`receiving_history_custody_bytes`, `root_public_key`, `work`, and optional
`live_window` / `transport_deadline_ns`. `_produce_on_work` replaces
`bootstrap_bytes` with the owned `payload` and adds `root_private_key`, genuinely
admitting the same originals before signing. No material/result DTO is an input.

The four detached originals are bound by exact byte-count/SHA-256 descriptors.
Admission selects only [SQL-issuer receiving v3](oidc-session-activation-delivery-execution-custody-bootstrap.md#separate-reserve-and-pending-receiver-profiles),
which genuinely admits consume planner v2, planning history v2 and separate
SQL-issuer history v5. Grant and reserve receiving scopes cannot substitute.
The role independently binds receiver identity, configuration, generation,
runtime closure, database ID, query-manifest digest and complete before-vector
digest. Returned `before_vector_bytes` comes from the authenticated complete
planner original, never the reserve ACK or client body. It is original evidence,
not a latest-head observation.

Current-root, consume-grant and consume-caller enrollment originals are decoded
under their exact caps and independently verified against the real root. Their
identities, database/generation and exact current-root original must agree with
the planner and role. The source fixes operation
`oidc.session.activation-delivery.consume`; generic original replay/grant
dispatch remains closed. Protected SQL selects a dedicated consume packet
branch with its own exact original inventory, domains and frame bounds.

## Independent pending and attempt scope

The root-signed `statePredecessor` is `{sequence, headDigest, nextFence}`;
`currentPending` is `{sequence, headDigest, fence}`; `attemptCheckpoint` is a
separate `{sequence, headDigest}`. Pending sequence must be predecessor plus one
and its fence must equal `nextFence`. Genesis predecessor is the genuine
current-root enrollment digest with fence one. There must be enrolled space for
completion and unused local capacity for an attempt.

An empty attempt chain must match the actual source/catalog-bound
`authority_successor_execution_attempts._genesis_on_work` digest. Neither an empty
directory nor a returned ACK supplies a checkpoint. The pinned attempt directory
must differ from both consume and historical activation original/export
directories. Its eventual exact owner must durably spend an attempt before SQL
and retain uncertainty; this bootstrap performs no journal I/O or recovery.

The [pending admission library](oidc-session-activation-delivery-pending-admission.md)
must later compare genuine original reserve/snapshot/ACK against these root-held
pins using an actual `for_sql_issuer` custodian and the original current allowance.
A signature authenticates who supplied the pins; it does not independently
observe that the pending head is still latest.

## Declared cold resources

The exact inherited descriptor inventory is fixed, not caller-selectable:

| FD | Original/resource |
| --- | --- |
| 198 | Root public key |
| 199 | SQL role bootstrap |
| 200 | Fixed private listener |
| 201 | SQL-issuer receiving custody |
| 202 | Consume planner bootstrap |
| 203 | Planning-history original |
| 204 | Separate receiving-history original |
| 205 | Consume execution-bundle AES key |
| 206 | Historical activation-bundle AES key |
| 207 | Historical delivery AES key |
| 208 | Separate attempt-journal directory |

The listener is `/run/serverware/oidc-session-activation-delivery-execution/sql.sock`.
The attempt directory is
`/var/lib/serverware/oidc-session-activation-delivery-execution-sql-attempts`.
Future delivery must enforce owner 65498, mode 0700, original device/inode and
exact FD continuity. These paths and three root-authenticated AES pins do not
create or deliver keys, accounts, descriptors or socket permissions. No planner,
grant, computation or completion signing key is available to this role.

Five TLS files have fixed paths under
`/run/serverware/oidc-session-activation-delivery-execution-sql-tls/`:
`ca.pem`, `issuer.crt`, `issuer.key`, `executor.crt`, `executor.key`. Each has a
root-pinned byte count and digest; keys are at most 16 KiB, certificates/CA at
most 64 KiB. Issuer/executor identity tuples, certificate pins and key pins must
be distinct. No supplied DSN, password, service file or arbitrary TLS path enters
the contract. Actual file validation, certificate authentication and lifecycle
checks remain future cold-delivery obligations.

`issuer_configuration` and `executor_configuration` are exact eight-tuples:
`(dsn, connect_timeout_seconds, role, tls_client_dn, tls_client_serial,
tls_issuer_dn, query_manifest_digest, expected_structure_manifest_digest)`.
The roles are source-fixed `serverware_policy_authority_successor_issuer` and
`serverware_policy_authority_successor_executor`. DSNs use the closed root-pinned
endpoint, `sslmode=verify-full`, fixed TLS paths, `passfile=/dev/null` and disabled
GSS encryption. These match existing resource-owner constructor fields, not an
implemented consume producer. A catalog-checked owner must still establish the
real database/role/TLS/structure bindings; these assertions do not prove both
connections reach the same database or grant consume SQL permission.

## Lifetime and unfinished connection

A supplied processing window is never replaced. The optional cold form uses
one neutral `_construction_on_work` opening before crypto; future entrypoint and
startup must explicitly carry that same window/bound through key/TLS/journal
delivery. The role and all four current receiving/planner/history intervals
remain live on the same cumulative work and inherited deadline. The later
`opening_sample` is a launch check, not permission to reopen processing. The old
activation planner remains history; its expired interval is not renewed.

Still required: fixed OS delivery/privilege drop and startup, actual independently
pinned cold pending admission, a genuine dedicated consume issuance/packet path,
IDs-only one-use SQL execution and durable attempt handling. Generic SQL continues
to reject consume. Completion/recovery, exact committed-token release, public
permission and production verification remain separate work.

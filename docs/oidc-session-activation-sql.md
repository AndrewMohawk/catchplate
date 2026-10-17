# Activation original admission and protected SQL

This is source composition, not deployment or exercised database evidence.
[authority_oidc_session_activation_sql.py](../catchplate/authority_oidc_session_activation_sql.py)
connects genuine activation pending admission to the actual
`SuccessorExecutionIssuer.issue`, then the IDs-only
`SuccessorExecutionExecutor.execute`. It never invokes the legacy session helper
or accepts a successful admission/transition object as input.

## Original inputs and independent scope

`_execute_on_configuration` takes the existing pending-admission keyword inputs
plus the actual issuer and executor owners: signed caller authorization,
plan/encrypted-bundle raw2, closed expectation data, grant, reserve/snapshot/ACK
raw3, the three enrollment originals, actual public keys, configuration digest,
independently held before-vector, predecessor and current-pending pins, actual
`sql-issuer` receiving custody, and the original work/window/inherited deadline.
No request-selected roots, keys, database identity or clock allowance is added.

The pending module's public `_admit_on_work` still returns unchanged raw3.
Its private `_admit_for_sql_on_work` suffix genuinely verifies the current caller,
grant, private original plan, signed reserve, exact snapshot and ACK, then joins
the independent predecessor, pending sequence/head/fence, database/generation
and before-vector. It derives issuer arguments, the exact expected marker and
a live guard only for this invocation. No entrypoint accepts that result.

The ACK is not its own current-head authority. Root-authenticated cold pending
pins are independently supplied scope, not proof of fresh off-host authority.
The protected database path must still perform its actual roots/row-lock/CAS,
role/TLS, catalog/query and one-use checks. Matching issuer/executor catalog pins
does not establish their database identity or equate their distinct TLS roles.

## One issuer and one executor

The issuer receives the genuine original arguments and replays them under the
remaining same work allowance before constructing its protected packet. The
activation plan-originals bundle remains ciphertext in that packet; signed
controls and token-free effects are not described as encrypted. No private
receiving owner, AES key or plaintext token is serialized to SQL.

Only the actual issuer's returned pending-decision and packet digests reach the
executor. Its actual attempt owner durably claims that pair before connecting
for execution. The claim is not cleared after timeout, rollback, mismatch,
late failure or uncertain commit. This bridge has no reissue/retry branch.

After normal outer commit, the bridge compares both returned IDs and every
canonical marker field against the genuine same-call expected marker, including
`operation = oidc.session.activate`. The result remains unsigned observation.
It does not release a browser token, sign completion or authorize a public
session-activation response.

## Lifetime and uncertainty

The private frozen return has exactly `observation`, `live_window`,
`deadline_ns` and `live`. The observation is the actual executor result; the
other fields retain the same-call guard for the fixed service's response.
Original opening samples are preserved while the reserve and actual issuance
expiry can only narrow the window/deadline. Actual owner/PID/attempt continuity,
current clocks and original caller/grant expiry are rechecked through return.
The service must use this guard and bound through serialization and sending.

Ordinary post-issuance failure raises `OidcSessionActivationSqlOutcomeError`
with only the two actual validated issuer IDs. Failure without those returned
IDs cannot manufacture them from request fields. `BaseException` propagates.
No uncertainty means absence, an unused attempt or permission to retry.

See the [fixed raw8/raw4 transport](oidc-session-activation-sql-transport.md)
and [durable reservation](oidc-session-activation-reservation-delivery.md).
Completion/recovery, public present-purpose permission and token delivery are
separate work. No build, test, database execution or provisioning was performed
for this source-only implementation.

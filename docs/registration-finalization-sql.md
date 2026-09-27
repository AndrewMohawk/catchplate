# Private finalization SQL composition

This source-only slice connects genuine `webauthn.registration.finalize`
originals to the actual protected successor issuer and executor. It is partial
F06 implementation, **not** a public execute action, deployed credential-finalization
workflow or OIDC activation. A separate [cold SQL worker](registration-finalization-sql-service.md)
and [private caller](control-plane-finalization-sql.md) now connect this composition
in source. The source is unbuilt and unexecuted; production acceptance remains
**0/6 verified**.

## Inputs and independent authority

[`authority_registration_finalization_sql._execute_on_configuration`](../serverware/authority_registration_finalization_sql.py)
accepts the independently admitted configuration/generation/runtime identities,
three original finalization-caller/grant/current-root enrollments, root public
key, current pending sequence/head/fence, one existing `live_window`, required
`transport_deadline_ns`, supplied work allowance and the actual
`SuccessorExecutionIssuer` and `SuccessorExecutionExecutor`. Original inputs are:

| Inventory | Exact originals |
| --- | --- |
| Finalization raw10 | Dedicated authorization, custody/planning raw7, complete before-vector, finalization execution grant |
| Reservation raw3 | Signed reserve request, computation snapshot, signed state acknowledgment |

The actual [original-admission module](../serverware/authority_registration_finalization_sql_admission.py)
authenticates the dedicated authorization, custody, complete plan/grant/vector
and reservation/pending commitments. Its private same-call arguments and live
checker are not accepted as external proof objects. The composition also fixes
the operation to finalization; the evidence-admit purpose is not substituted.
The actual issuer retains its own complete packet preparation/replay before
protected database issuance. No incoming packet bytes or custody locator can
bypass either path.

The caller must separately authenticate the present actor and finalization
execution purpose. A preparation/reservation action, retained record identifier
or genuine acknowledgment does not supply that permission. Independently
expected **current** pending pins must not be copied from the returned reserve
acknowledgment. A signed historical acknowledgment does not establish that its
head is still current at action time.

## Actual owners and irreversible execution

The composition holds exact issuer/executor types, process identities,
immutable eight-field configurations and the executor's actual attempt-owner
identity before callbacks. After genuine admission captures caller inputs, it
uses the actual class-method snapshots to check configuration continuity and
the catalog-bound attempt journal's readiness before issuance. This is neither
a fabricated checkpoint nor a fresh currentness witness.

Issuer and executor retain their distinct fixed database roles and admitted
TLS identities. Their query and structural-catalog pins must agree; this does
**not** establish database identity, certificate provenance or deployment
admission. The cold owner must independently admit the intended database,
each role's connection/TLS material and the protected attempt journal/checkpoint.
No DSN is inferred from originals, and comparing or parsing DSNs is not used to
manufacture provenance.

Only `SuccessorExecutionIssuer.issue`'s actual returned pending-decision and
packet digests reach `SuccessorExecutionExecutor.execute`. They are not a
control-plane grant or reservation `localDigest`. The executor irreversibly
records its attempt before opening execution SQL; this composition never
releases the claim, replaces the packet or retries issuance/execution. The
returned `SuccessorExecutionObservation` must match both same-call custody IDs.
It observes the normal outer commit of the protected operation; it is unsigned
and is not a separately signed completion or a current-head assertion.

All phases share the original work and clock bracket, with sticky wall/monotonic
rollback checks and actual owner continuity around the operations. A shorter
expiry returned by real issuance additionally clips the executor window and
monotonic bound while preserving its original opening samples. No fresh window
or extended grant is created. Userspace deadline checks are not a hard watchdog
for filesystem locks, driver behavior or database work.

## Failure and remaining integration

Issuance can fail after durable custody; execution can fail after its attempt
claim or commit. An ordinary issuance error returns a static
`RegistrationFinalizationSqlError`, with no invented locators. Once actual
issuance returns two validated IDs, ordinary subsequent failures raise
`RegistrationFinalizationSqlOutcomeError` carrying only
`pending_decision_digest` and `packet_digest`. These identify originals for a
future genuine reconciliation path, not success, absence of side effects or
retry permission. Cancellation propagates. No raw input, key, DSN or driver
exception text is included in those outcome errors.

The [reservation flow](control-plane-finalization-reservation.md) remains a
separate operation. This slice adds no caller-facing execution endpoint or
control-plane outcome association. The dedicated worker and private caller
use the [raw13/raw4 transport](registration-finalization-sql-transport.md).
Independently admitted action-time pending scope, protected service/database/journal
provisioning, separate signed completion/recovery and the complete portal
workflow still require integration. OIDC session activation remains its own
authenticated transition after actual credential finalization. No services,
keys, SQL privileges or journal checkpoints were provisioned by this work.

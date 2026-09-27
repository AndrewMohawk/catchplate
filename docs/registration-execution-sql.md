# Registration evidence SQL execution bridge

This source-only bridge connects genuine registration originals to the actual
[protected successor issuer and executor](authority-successor-execution.md).
Its fixed operation is `webauthn.registration.evidence.admit`: admission of the
registration evidence business row, not credential finalization or session
activation. It is unbuilt and unexecuted; **0 of 6 production acceptance gates
are verified**. No cold SQL service or public execution path is activated.

The existing [public reserve endpoints](control-plane-registration-reservation.md#public-reserve-endpoints)
remain reservation-only. Their acknowledged status is not upgraded into SQL
permission, and their `executionStarted` and `currentnessEstablished` flags
remain false.

## Originals and independent admission inputs

The bridge consumes two exact original inventories:

| Inventory | Original bytes |
| --- | --- |
| Grant raw10 | Caller authorization, signed planning request3, signed planning response4, complete before-vector and signed execution grant |
| Reservation raw3 | Signed reserve request, computation snapshot and signed state acknowledgment |

Configuration/generation and enrollment originals are independently supplied;
the actual planner/evidence keys come from that admitted configuration and root
scope. A browser-supplied expectation graph, local content ID or prior
successful-verification object is
not a replacement. The bridge authenticates caller/grant controls before the
actual issuer performs the complete generic semantic, plan, pending-reservation
and grant replay once. Local storage association is not that replay.

A future owning service must authenticate the present caller and the execution
purpose before invoking this private entrypoint. Possession of preparation,
grant or reservation originals is not consent for a public execute action.
The existing reserve purpose authorizes reservation only.

The expected **current pending sequence, head and fence** must come from an
independent current authority. They must never be copied from the incoming
acknowledgment to make it match itself. A genuine signed acknowledgment can
describe a reservation that is no longer pending. The reserve predecessor pins
and historical receipt checks in the earlier handoff do not supply this later
action-time currentness gate.

## Private source interfaces

[`authority_registration_execution_sql_admission._admit_on_configuration`](../serverware/authority_registration_execution_sql_admission.py)
accepts the original inventories, configuration digest/payload, generation and
runtime role identities, the three original caller/grant/current-root
enrollments, root key, independently expected pending sequence/head/fence,
original epoch/monotonic deadlines and existing work budget. It returns private
same-call issuer arguments and live-window guards, not a publicly accepted
admission token. It performs no database operation or signing.

[`authority_registration_execution_sql._execute_on_configuration`](../serverware/authority_registration_execution_sql.py)
accepts those same original inputs plus the actual `SuccessorExecutionIssuer`
and `SuccessorExecutionExecutor`. It checks the retained process/configuration
and actual attempt-owner readiness, invokes the issuer, and passes only that
call's actual custody identities to the executor. It returns the actual
`SuccessorExecutionObservation`, not a new signed receipt or completion.

## Actual issuer and one-use executor

```text
raw10 + raw3 + independent configuration, keys and CURRENT pending scope
    -> authenticate original caller/grant controls
    -> actual issuer: complete generic replay and protected issuance
    -> actual returned pending/packet identities (not the local grant ID)
    -> durable irreversible attempt claim
    -> actual protected executor SQL
    -> committed evidence or uncertain outcome; never automatic execution retry

signed completion and credential finalization: separate owners and operations
```

This composition requires the real PostgreSQL issuer and executor owners with
independently admitted per-role TLS identities and database roles. Their
independently supplied query and catalog/structural pins are not learned from
the incoming grant or accepted
from a posted successful-inspection result. No arbitrary SQL, role selection or
caller-selected database operation is added. The composition requires equal
query/catalog pins; independent provisioning must establish that the distinct
role-specific connections address the same intended database. It does not infer
that provenance by comparing or parsing DSNs, or establish TLS identity
separation merely by comparing the query/catalog pins.

The executor's actual separate attempt journal is admitted with its own
independent local checkpoint and protected storage. It records the one-use
attempt before the executor's database work. The control-plane grant journal,
signer association marker and reserve-delivery journal cannot replace it.
An attempt is not cleared when transport or database work fails, even if a
caller believes nothing was sent.

Only identities actually returned by protected issuance may select the next
execution step. The control-plane `localDigest` identifies a retained grant
bundle; it is not a pending-decision digest or execution-packet digest.
Return values from individual stages do not create a general success capability
or bypass the actual owners' remaining admission checks.

Protected issuance may return an expiry shorter than the grant's. Execution
uses that tighter expiry within the same original opening window and work
budget; it does not open a new clock interval or renew authorization.

## Uncertainty is not retry permission

Issuance can fail after durable database effects. Execution can fail after its
attempt claim or after a commit. Missing results, exceptions and interrupted
delivery establish neither absence nor rollback. The composition does not
automatically retry issuance, regenerate/sign a grant, clear an attempt or run
execution again.

An uncertain issuance raises a static `RegistrationExecutionSqlError` without
locators. Only after actual successful issuance can
`RegistrationExecutionSqlOutcomeError` carry `pending_decision_digest` and
`packet_digest` for reconciliation. Those actual custody locators establish
neither execution success nor failure and are never replaced with the
control-plane grant ID. Cancellation propagates rather than becoming a
successful observation or retry instruction.

The trade-off is deliberate: uncertain outcomes stop progress until genuine
protected reconciliation establishes what happened. This can leave a spent
attempt or retained pending records without an immediate successful response;
it does not permit a second execution across the uncertainty boundary.
Original windows and work bounds are not renewed to make reconciliation into
new execution authority. Local filesystem durability still depends on the
provisioned storage and is not an independent anti-rollback witness.

## Completion, finalization and provisioning remain separate

No completion private key is introduced here. Genuine
[completion recovery](authority-current-root-completion.md) still requires its
separate UID65515 owner, key, journal, protected committed-marker/full-vector
readers and independently current checkpoint. Only actual committed evidence
can support a signed completion; a successful reserve or an executor call is
not a fabricated completion receipt.

Credential finalization is the separate `webauthn.registration.finalize`
operation. It still requires the actually committed evidence business row,
genuine replay of the [associated original signer exchange](control-plane-custody-journal.md#associated-registration-preparation),
and its own authorization/currentness/one-use gates. This bridge does not
complete that workflow.

Independent current-state authority, PostgreSQL accounts/TLS material and
privileges, query/catalog pins, key and journal provisioning, cold SQL service
composition, public action admission and deployment remain external or later
integration work. Source presence does not close any production acceptance gate.

# Dedicated consume custody issuance

[`authority_oidc_session_activation_delivery_execution_packet.py`](../catchplate/authority_oidc_session_activation_delivery_execution_packet.py)
connects genuine [current pending admission](oidc-session-activation-delivery-pending-admission.md)
to the actual protected successor issuer. It does not accept a successful
candidate, returned effects, caller packet or pluggable verifier as authority.
Generic consume replay, grant and packet-preparation dispatch remain closed.

## One original replay, then real custody

The private `SuccessorExecutionIssuer._issue_delivery_on_work` takes the complete
keyword-only pending-admission input set: signed caller authorization, signed
consume grant, immutable plan/ciphertext raw2, reserve/snapshot/ACK raw3, original
root/enrollments, independently held configuration and planner/operation keys,
expected request/scope, complete before-vector, predecessor and current-pending
database/generation/sequence/head/fence, actual SQL-issuer receiving custody,
and the caller's original work/window/positive inherited deadline.

The genuine receiver must be separately root-admitted for UID/GID 65498 and
the SQL-issuer purpose. Caller/grant controls are authenticated before private
opening; the actual consume plan is replayed once. The full replay retains
selected rows from its actual invocation context, not a received result carrier.
The independently checked pending ACK supplies no expected current checkpoint.
Only this invocation's proof-derived selected rows, three mutations, token-free
result and complete before/after vectors enter the candidate and exact marker.

The original reserve interval is preserved. The caller, plan, grant, receiving
launch and reserve guards remain current through packet creation, actual SQL
insertion, normal connection closure and return. No work allowance, clock
opening, original expiry or process purpose is renewed.

The issuer calls the real protected PostgreSQL custody function on its fixed
role/TLS connection. It checks the independently admitted complete source
catalog before the call and before outer commit. Immutable insertion/readback
must match the exact packet and issuer; no source candidate is called a SQL
result. `_IssuedDelivery` is ordinary same-call output with fields
`observation`, `marker_expectation`, `live_window`, `deadline_ns`, `live`;
`live()` returns a current epoch integer. No input API accepts that carrier.

## Closed packet and storage branch

The neutral `policyAuthoritySuccessorExecutionPacket/v1` schema and identity
domain remain unchanged. Consume has a fixed nine-key originals inventory:

- `currentRootEnrollment`, `grantEnrollment`, `grant`;
- `reserveRequest`, `reserveReceipt`, `computationSnapshot`;
- `callerEnrollment`, `callerAuthorization`;
- `plan`, containing exactly signed consume plan and encrypted bundle.

Only the private bundle is opaque ciphertext: controls, selected rows, effects
and result remain ordinary token-free JSON. Neither plaintext tokens nor AES
keys enter SQL. The existing 64 MiB packet ceiling includes base64 originals;
per-frame limits and cumulative work also apply and do not promise every
individually valid input will fit the remaining allowance.

The SQL renderer selects one exact consume branch for its distinct caller,
grant/enrollment and computation schemas/domains and raw2 maxima. It checks
canonical frames, exact commitments, caller post-plan timing, reserve lifetime,
marker and source effect limits. Other families retain their existing branch.
SQL does not verify Ed25519 or replay proofs: the separately pinned original-only
Python issuer is the trusted authentication/replay boundary, as for existing
successors. A hostile schema owner or host remains outside that guarantee.

The existing executor still accepts only pending-decision and packet digests.
It durably claims an attempt before DB access, reads immutable custody, and
performs selected-row checks, source compare-and-swap effects, maintained full
roots and the unique commit marker in the actual outer transaction. Uncertainty
never clears the attempt or authorizes automatic reissue/retry. This issuance
path itself neither executes the packet nor reports signed completion.

## Remaining boundary

Protected recovery can retain/read exact packet bytes without renewing their
execution interval; genuine consume historical completion, reconciliation and
token-release admission are separate unfinished consumers. No current-session,
plaintext-token, public-permission or portal-success claim follows from packet
custody or an unsigned SQL observation.

This is source implementation only. No import, parser, build, test, SQL execution,
installation or provisioning was performed, and no runtime or production
acceptance is claimed.

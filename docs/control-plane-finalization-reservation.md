# Control-plane finalization reservation scope

Source-only implementation; unbuilt, unexecuted and unprovisioned. This is a
dedicated finalization reserve exchange, not protected SQL execution, completed
credential registration, OIDC activation or independent currentness evidence.

## Explicit cold scope

[The nested bootstrap](../serverware/control_plane_registration_finalization_bootstrap.py)
admits `serverware.controlPlaneRegistrationFinalization/v2` only inside the
existing root-signed control-plane parent v4. An explicit nested v3 extension
below adds SQL endpoint/current-pending configuration only. Nested v1 remains unchanged and
grant-only; it has no reservation endpoint or predecessor. No new key descriptor,
environment fallback, key generation or evidence-admit permission is added.

The closed v2 object has the original six fields (`schema`,
`finalizationCallerPrivateKeyFd`, `currentRootEnrollment`, `grantEnrollment`,
`authorizationEnrollment`, `authorizerEndpoint`) plus:

| Field | Exact contract |
| --- | --- |
| `reserverEndpoint` | `{socketPath, requestTimeoutSeconds, listenerUid, listenerGid}`; path `/run/serverware/registration-finalization/reserver.sock`, integer timeout 1–30 seconds, listener UID/GID `0:0`. |
| `statePredecessor` | `{sequence, headDigest, nextFence}`; independently root-signed sequence, canonical SHA-256 head and positive fence. |

FD 204 remains the dedicated finalization caller key. The actual configured
finalization planner/operation keys, original caller/grant/current-root
enrollments and root are authenticated using the parent's supplied work. The
current-root enrollment must match the caller, database and configured
generation. The predecessor must leave two enrolled record slots for reserve
and completion. At sequence zero, the head must equal the actual enrollment
identity and `nextFence` must be one. A returned acknowledgment never supplies
these independent pins. The root listener peer identifies socket activation,
not the later reserver signing identity.

The private cold material retains `reservation_endpoint` and
`reservation_predecessor`; both are `None` for v1. See the
[caller custody contract](control-plane-registration-finalization-custody.md)
for parent admission and key custody.

## Opt-in current-pending pins, not a witness

`serverware.controlPlaneRegistrationFinalization/v3` is exactly the eight v2
fields plus `sqlEndpoint` and `currentPending`, under the same signed parent
v4 and dedicated FD204. Nested v1/v2 remain unchanged and do not gain SQL
configuration implicitly.

`sqlEndpoint` has the closed endpoint shape above, with fixed path
`/run/serverware/registration-finalization/sql.sock`, integer timeout 1–30
seconds and root-activated listener peer `0:0`. `currentPending` is exactly
`{sequence, headDigest, fence}`: a positive sequence, canonical SHA-256 head
and positive fence. Its sequence must equal the independently root-signed
`statePredecessor.sequence + 1`, and its fence must equal that predecessor's
`nextFence`. Actual admission of the original current-root enrollment requires
the pending sequence to remain below its enrolled record limit, preserving
completion capacity.

The private material retains `sql_endpoint` and `current_pending`; both remain
`None` under v1/v2. The owner exposes `finalization_sql_enabled` as a
configuration-presence check with its existing live-owner guard. It performs no
SQL dispatch, database query, nonce lookup or current-head observation. There
is no new key, descriptor or environment variable.

The head must be independently supplied in the signed cold bootstrap, never
copied from the reserve acknowledgment or local reservation slot. Root signing
authenticates the assertion's origin, not its continuing truth at action time.
Even the existing nonce-bound state-owner lookup is an authenticated observation
of that owner's state, not independent hostile-host antirollback or an atomic
off-host action-time lease. The separate SQL caller still needs genuine original
pending/grant/plan admission and the actual protected database checks; static
pins do not close the external currentness/one-use production gate.

The [private SQL caller](control-plane-finalization-sql.md) and [cold worker](registration-finalization-sql-service.md)
now connect those independently admitted pins to genuine original verification
and protected SQL composition in source. The configured property itself is
still not a request or proof of execution. A separate [public SQL action](public-registration-finalization-sql.md)
now requires its own present permission and retained ownership/claim/outcome
path. Completion/recovery and external action-time authority remain open; the
reservation path does not automatically invoke the SQL path.

## One original-bound exchange

[The actual enrollment owner](../serverware/control_plane_enrollment_startup.py)
exposes `finalization_reservation_enabled` and the private method
`_request_registration_finalization_reservation(*, originals, live_window,
transport_deadline_ns, work)`. The method requires raw10, in order:

1. The original dedicated finalization authorization.
2. The seven original finalization custody/planning objects.
3. The original complete before-vector.
4. The original finalization execution grant.

[`_reserve_on_owner`](../serverware/control_plane_registration_finalization_execution.py)
retains the actual cold owner, configuration, keys, PID and custody binding via
the existing `_scope`. It genuinely replays the complete finalization grant and
custody originals before contacting the fixed reserver once. It keeps that
admission's live checker across transport and final return; the original caller,
plan and grant intervals must still be live when the exchange completes.

The endpoint timeout starts at the supplied window's original monotonic opening,
not after replay or connection. It only narrows the inherited deadline. There
is no replacement work allowance, renewed window, reconnect or automatic retry.
Request/response frame and group caps apply, and all raw10, returned raw3 and
three enrollment originals together must fit the existing 64 MiB aggregate.

After transport, the genuine [receiving verifier](registration-finalization-reservation.md#live-receiving-verification)
authenticates the live signed reserve request, reconstructs the exact computation
snapshot from complete replay, and checks the original signed state receipt
against the independently held predecessor and fence. The method returns only
the unchanged `(request, snapshot, acknowledgment)` raw3, not a proof token,
latest-head assertion or SQL authority. Historical receipt checks supplement,
and never replace, this live original admission.

## Separate responsibilities and uncertainty

Present operator/session ownership and the explicit reservation purpose must be
admitted before this private method. Cold configuration alone is not that
permission. This module neither exposes a public route nor writes a returned
custody association; callers must separately retain the genuinely verified
originals before presenting their durable local identifier.

The [dedicated reserver](registration-finalization-reserver.md) and its
[original delivery journal](registration-finalization-reservation-delivery.md)
own remote reserve delivery and uncertainty. An exception after a possible send
can mean remote state changed; it does not authorize another automatic send.
A successful acknowledgment is not independent latest-state evidence. Protected
pending-head/SQL/outcome/completion integration, credential finalization and
separate OIDC session activation remain distinct obligations. Deployment also
requires independently admitted roots/keys/checkpoints, actual state-v2 peer
configuration, filesystem/socket permissions and consolidated frozen
verification; none is established by these source files.

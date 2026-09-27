# Private control-plane registration reservation handoff

This source-only, opt-in composition carries genuine registration preparation
through the [cold reserver](registration-execution-reserver.md) and independent
verification of its original response. It is unbuilt and unexecuted. Existing
public HTTP handlers still prepare and retain grants with associated signer
originals; none calls this new facade. It adds no public execution endpoint, automatic reservation upgrade,
SQL execution or credential finalization.

## Explicit cold opt-in

The parent signed
`serverware.signedControlPlaneEnrollmentBootstrap/v3` and
`serverware.controlPlaneEnrollmentBootstrap/v3` profiles are unchanged.
Within `registrationExecution`, the closed six-field
`serverware.controlPlaneRegistrationExecution/v1` remains grant-authorizer-only.
Null still disables this scope. Neither is silently promoted.

The new closed `serverware.controlPlaneRegistrationExecution/v2` has the same
six fields, with its own discriminator, plus exactly:

| Field | Independently provisioned contract |
| --- | --- |
| `reserverEndpoint` | `{socketPath, requestTimeoutSeconds, listenerUid, listenerGid}`; fixed `/run/serverware/registration-execution/reserver.sock`, integer 1–30 seconds, listener `0:0` |
| `statePredecessor` | `{sequence, headDigest, nextFence}` for the intended reserve; not copied from the response or local journal |

The [nested bootstrap verifier](../serverware/control_plane_registration_execution_bootstrap.py)
authenticates the three original enrollments and their configuration/generation
joins, checks enrolled capacity, and binds a genesis predecessor to the genuine
enrollment identity and fence one. The complete parent original remains signed
and bounded to 4 MiB. The same dedicated caller key remains at **FD203**; no new
key, environment slot, computation key or state-signing key is delivered to the
control plane. The [early FD projection](../serverware/authority_fd_entrypoint.py)
checks both closed shapes without substituting for child cryptographic admission.

`reservation_enabled` on the actual [cold enrollment owner](../serverware/control_plane_enrollment_startup.py)
requires both admitted v2 endpoint and predecessor, in addition to its actual
caller key and live custody. A successful response does not update these pins.
The caller's independently admitted scope must match the reserver's fixed
predecessor/fence; a signed acknowledgment cannot appoint a later checkpoint.

## One original preparation window

The private application API is
[`prepare_and_reserve_registration_execution(originals)`](../serverware/control_plane_registration_preparation.py).
It returns `(existing_local_grant_id, (reserve_request_bytes, snapshot_bytes,
state_acknowledgment_bytes))` only after the complete original response is
genuinely verified. This is not an HTTP response or a transferable permission
object.

The authenticated application must first admit the present actor/session and
the explicit new-purpose permission to reserve. Possession of an original-input
container, local grant ID or old evidence-signing permission does not provide
that admission. Nested-v2 cold scope is required before preparation begins.

```text
present caller and purpose admission
    -> genuine preparation: grant raw10 + same signer request8/response2
    -> durable signer record + grant record + final association marker
    -> authenticate original grant before one fixed raw10 reserve exchange
    -> independently verify original reserve + snapshot + state acknowledgment
    -> return existing grant ID and unchanged raw3; no SQL dispatch
```

One preparation work allowance and its original wall/monotonic window cover
the entire composition. Storage, replay, transport and response checks may
only consume or narrow those bounds. The complete
[signer/grant association](control-plane-custody-journal.md#associated-registration-preparation)
is retained before the reserve send. Retention may succeed after the grant
expires, but that does not permit the next send or create another window.

The owner method `_request_registration_reservation(originals=...,
deadline_epoch_ns=..., deadline_ns=..., work=...)` delegates to
[`_reserve_on_owner`](../serverware/control_plane_registration_execution.py).
It verifies the original permission/grant before contacting the fixed reserver,
then uses the original request and independent cold scope to verify the returned
raw3. The original-only transport keeps its existing raw10 request and raw3
response caps, peer checks, absolute deadline, half-close and exact EOF; it has
no retry or alternate destination.

## What the returned originals establish

The [response verifier](../serverware/authority_registration_reservation_response.py)
performs genuine planning and purpose verification, full grant/plan/vector
replay, live computation-signature verification, exact snapshot reconstruction,
and state-acknowledgment signature and scope joins. Expected predecessor/head/
fence come from the independent cold bootstrap, not from the response. It
returns only the unchanged three originals under the same work and original
clocks, with final freshness checks.

An authentic acknowledgment is **not an independently current pending-head
authority**. The receiver does not turn its reported head into the expected
head of a successor-execution admission call. Another state transition may
have occurred. Action-time currentness, atomic one-use SQL admission, protected
execution and completion remain separate gates.

An original response can be authentic but already expired: this live receiver
rejects it. The service's separate same-original historical receipt recovery
does not relax that rule or renew a grant. Do not treat live rejection as proof
that reservation did not occur.

## Uncertainty and deployment prerequisites

An ordinary failure after append returned the actual durable grant ID raises
`RegistrationReservationOutcomeError` with that ID in `local_digest`. This
preserves a local locator only, not a receipt, remote outcome, safe retry or
permission. Cancellation propagates. Failures during publication may retain
partial originals; failures after sending may follow actual state acceptance.
No stage automatically retries preparation, signs again or reserves again.

The fixed caller key source
`/run/secrets/serverware-registration-execution-caller-key`, signed bootstrap,
original enrollments and journal must be independently provisioned. Socket
directories must actually be visible in the control-plane runtime; the current
production Compose configuration does not supply the caller-key source or the
registration-evidence/execution socket mounts. Packaging source alone is not
such delivery.

The reserver socket is 65514:65532 mode 0660, admitting the actual control-plane
primary identity once correctly mounted. Its root-created listener is checked
as `0:0`; this does not imply hardware custody. The separate state socket remains
65516:65516 mode 0660 and requires narrow provisioned access for reserver UID
65514, which has no supplementary groups. A bind mount alone does not grant
that access or broaden the state peer allowlist.

Public route/actor admission, action-time current-head authority, protected SQL,
completion and separate credential finalization are not activated by this
private handoff. No production acceptance gate is closed.

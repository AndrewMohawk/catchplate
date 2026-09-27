# Public retained-finalization reservation

The source implements a separate, explicit reservation action for an already
retained **finalization grant**. It neither prepares a grant nor reserves an
evidence-admission locator. Source is unbuilt, unexecuted and unprovisioned;
these routes and the portal action have not been browser-verified or admitted
for production.

The [routes](../serverware/control_plane_registration_finalization_reservation_routes.py)
are:

- `POST /api/webauthn/register/reserve-finalization`
- `POST /api/auth/session/webauthn/register/reserve-finalization`

Both require strict, bounded 64 KiB JSON with `purpose` equal to
`reserve-registration-finalization`, and `localDigest` equal to the retained
finalization-grant ID returned by [grant preparation](public-registration-finalization-grant.md).
Only optional `bootstrapToken` and `mfa` carriers are also accepted. Posted
subjects, roots, keys, timestamps, before-vectors and successful verification
objects are not inputs. The distinct action is
`webauthn.registration.finalization.reserve`.

## Genuine ownership before present permission

The [facade](../serverware/control_plane_registration_finalization_reservation.py)
loads the actual finalization association and its existing evidence/signer
association from the cold custody owner. It authenticates the original
finalization authorization, custody raw7, complete before-vector and grant,
and replays the genuine associated signer/evidence exchange and stored
acknowledged evidence completion under the independently configured pending
scope. An unsigned journal marker or matching user ID is insufficient.

The fully replayed finalization plan supplies only its proven sibling list as
reconstruction hints. The genuine signer verifier regenerates the complete
typed finalization request; the facade compares every request field and the
exact source-generated input bytes to the admitted plan. No new sibling query,
authorization signature or plan is created. All originals must remain live;
historical expiry exceptions do not permit this new action.

`inspect_retained_finalization_subject(local_digest)` returns exactly seven
ordinary fields: `localDigest`, `userId`, `challengeId`, `sessionId`, `mode`,
`requestDigest`, `operationId`. The local ID is the finalization-grant locator;
the request/operation identities come from the genuinely regenerated
**finalize** request. This output is not an authority token. The handler binds
these actual same-call values into the distinct reservation-purpose MFA and
approval intent.

Operators must have current admin/approver authority. Existing-credential
users require the genuine fresh mutation assertion under the configured
hardware-authentication policy and the action's two-person check. A first
enrollment requires a fresh bootstrap token even in development; an older
enrollment mode or grant-preparation permission cannot replace it. The pending
OIDC path requires an explicit matching CSRF cookie/header pair, fresh pending
session reads and no credential history. Both branches refresh the actual
caller/session and recheck credential history before dispatch.

## One explicit exchange, then durable originals

`reserve_retained_registration_finalization(local_digest, *, expected_user_id,
expected_session_id)` repeats the complete ownership check under the actual
enrollment-owner lock and compares the independently authenticated current
user/session scalars. One current work/window and the original endpoint cap
cover the replay and one [cold caller exchange](control-plane-finalization-reservation.md).
The actual owner separately verifies the original raw10 before sending and
genuinely authenticates the returned reserve request, snapshot and state
acknowledgment against independent predecessor/head/fence pins. No response
head becomes an expected scope.

The complete retained inventory plus returned raw3 must fit the 64 MiB source
aggregate. Only verified raw3 is durably appended under the original grant ID
through [dedicated retention](control-plane-custody-journal.md#retained-finalization-reservation).
An already-retained reservation is rejected rather than silently redispatched.
The facade returns `(same_finalization_grant_id, verified_raw3)` only after
append; no raw original is exposed over HTTP. Late failure may follow remote
or local durable effects, and does not remove retained bytes or grant retry
permission.

The [closed response](../serverware/control_plane_registration_finalization_reservation_http.py)
is HTTP `202` with exactly ten fields:

| Field | Value |
| --- | --- |
| `schema` | `serverware.webAuthnRegistrationFinalizationReservation/v1` |
| `status` | `reservation-recorded` |
| `purpose` | `reserve-registration-finalization` |
| `localDigest` | Original finalization-grant local ID |
| `operation` | `webauthn.registration.finalize` |
| `reservationRecorded` | `true` |
| `finalizationExecuted` | `false` |
| `registrationCompleted` | `false` |
| `currentnessEstablished` | `false` |
| `automaticRetryAllowed` | `false` |

Errors disclose no raw proof or credential material. Unknown outcomes remain
unknown with no automatic retry; a local ID is added only after genuine
ownership inspection. A reservation acknowledgment is not a currentness witness,
protected SQL permission/result, finalization completion, credential success or
OIDC browser-session activation. Those independent downstream gates remain.

The [portal handoff guide](portal-registration-handoff.md) describes the explicit
source-only reservation control. The [cold reserver](registration-finalization-reserver.md)
still requires independently admitted launch scope, state-service v2 and path
access. No handler installs or provisions those services.

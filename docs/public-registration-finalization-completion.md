# Public finalization completion and recovery

The source-only [HTTP contract](../serverware/control_plane_registration_finalization_completion_http.py)
and [routes](../serverware/control_plane_registration_finalization_completion_routes.py)
expose separate present-permission actions for the retained finalization grant
locator. They do not execute or retry SQL, activate an OIDC session, or turn an
unsigned SQL observation into authenticated completion. Fourteen focused
permission/diagnostic component tests passed on 2026-10-08, including the
two-person refusal and redaction controls. An authenticated admitted-owner
completion journey remains unexecuted; these checks are not production
acceptance evidence.

| Action | Operator POST | Purpose | Required action |
| --- | --- | --- | --- |
| Complete | `/api/webauthn/register/complete-finalization` | `complete-registration-finalization` | `webauthn.registration.finalization.complete` |
| Recover completion | `/api/webauthn/register/recover-finalization-completion` | `recover-registration-finalization-completion` | `webauthn.registration.finalization.recover` |

The same suffixes are available under `/api/auth/session/webauthn/register/`.
Both operator and pending-session actions have an additional `/options` POST. All eight
routes use strict 64 KiB JSON framing. Actions require exactly `purpose` and
`localDigest`, with optional `bootstrapToken` and `mfa`; options accept only
the two required fields. No caller-supplied subject, root, packet locator,
signature original or timestamp is accepted.

## Fresh permission and original ownership

Before permission, the handler genuinely inspects the retained finalization,
its evidence/signer association and acknowledged evidence completion. It joins
the full replayed finalization request and inputs to the same signer originals,
not just matching user IDs. The new eight-field subject additionally includes
the original credential ID. Its canonical unpadded base64url represents
1–1024 bytes. The exact action binding includes that ID, the user/challenge/
session/mode and original request/operation/local digests; the older generic
seven-field handoff contract is unchanged.

Operator requests require actual current admin/approver identity. Existing
credential history requires a fresh completion-bound possession assertion under
the current WebAuthn policy. Configured two-person completion currently refuses,
as described below. Genuinely empty
history requires fresh configured bootstrap, including development. Bootstrap
cannot replace existing-credential MFA. Identity and the history branch are
reread before dispatch, and the facade repeats genuine retained ownership under
the cold owner lock using authenticated user/session scalars, not a subject DTO.

The [pending-session permission flow](finalization-pending-permission.md)
requires explicit cookie CSRF, a fresh DB-time-valid pending session and current
RBAC. Empty history requires bootstrap. When the finalization's exact target is
the sole active credential owned by that user, a fresh target-key possession
assertion can authorize completion only when the action does not require
two-person approval. This does not activate the session. Foreign, revoked, extra
or inconsistent credential history is denied.

Pending `/options` responses contain exactly `schema`, `purpose`, `localDigest`,
`action`, `resourceId`, `payloadDigest`, `publicKey`, `expiresAtEpochNs`, and
`automaticRetryAllowed: false`, with schema
`serverware.webAuthnRegistrationFinalizationPermissionOptions/v1`. These are
actual server-generated action-bound options, not an accepted posted binding.

The [possession helper](../serverware/control_plane_registration_finalization_permission.py)
retains one random nonce on the admitted enrollment owner, bounded by its
original context and at most 120 seconds. It burns the nonce before signature
verification; rejection or an uncertain response does not permit reissue on that
owner. Owner loss/restart invalidates the nonce. No metadata challenge, stored
counter or `last_used_at`/`updated_at` write occurs. The observed counter must
still satisfy the existing strict counter rule against the unchanged stored
baseline. Session, credential and current policy are rechecked while preserving
the complete pending metadata vector.

## Current two-person boundary

If the selected complete or recover action requires two-person approval, both
operator and pending-session paths return HTTP 503 with fixed error
`registration_finalization_completion_two_person_unavailable` before options,
assertion consumption, bootstrap, approval writes or completion dispatch. This
also applies to an empty-history branch. There is no implemented 428 approval
negotiation or approval-continuation flow for these completion actions.

Generic approval creation/consumption and ordinary WebAuthn bookkeeping would
change roots that the completion service must match to the already committed
plan. A future integrated authorization protocol must resolve that boundary
explicitly; removing the guard, editing retained roots or wrapping the remote
completion call in a local transaction is not a supported solution. The fixed
503 diagnostic does not implement approval or authorize retry.

## Authenticated observation, not session activation

The actual retained facade uses the independently admitted cold completion
endpoint, packet locator, authorization digest and pending sequence/head/fence.
It verifies historical originals and real completion/state signatures under one
current processing window. An acknowledged stored response is reverified; a
first bounded response is retained as opaque data before semantic acceptance.
Only the explicit recovery action may fetch after uncertainty and append a
separate authenticated reconciliation. The original uncertain observation stays
retained. See [historical finalization admission](registration-finalization-history.md).

Successful `202` responses contain exactly nine fields:

- `schema`: `serverware.webAuthnRegistrationFinalizationCompletion/v1`, or
  `serverware.webAuthnRegistrationFinalizationCompletionRecovery/v1` for recovery;
- `status`: `finalization-completion-acknowledged`, or
  `finalization-completion-recovered` for recovery;
- the fixed `purpose` and same finalization-grant `localDigest`;
- `observationAuthenticated: true` and `finalizationAcknowledged: true`;
- `sessionActivated: false`, `currentnessEstablished: false`, and
  `automaticRetryAllowed: false`.

There is deliberately no ambiguous `registrationCompleted` flag. Structural
raw4/status checks alone cannot produce this result; the route projects only
the actual authorized facade's verified return. The wire has no packet-identity
claim and supplies no live external-head witness.

Unavailable outcomes expose a fixed purpose-specific error, `remoteState:
unknown`, the three false session/currentness/retry flags, and at most a
canonical local locator after genuine ownership. They do not assert that a
remote operation failed to commit. No raw originals or exceptions are returned.
Separate OIDC browser-session activation, independent cross-generation authority
resolution, provisioning and frozen end-to-end production verification remain
outside this source slice.

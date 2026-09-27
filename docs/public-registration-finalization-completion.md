# Public finalization completion and recovery

The source-only [HTTP contract](../serverware/control_plane_registration_finalization_completion_http.py)
and [routes](../serverware/control_plane_registration_finalization_completion_routes.py)
expose separate present-permission actions for the retained finalization grant
locator. They do not execute or retry SQL, activate an OIDC session, or turn an
unsigned SQL observation into authenticated completion. The implementation is
unbuilt, unexecuted and not production acceptance evidence.

| Action | Operator POST | Purpose | Required action |
| --- | --- | --- | --- |
| Complete | `/api/webauthn/register/complete-finalization` | `complete-registration-finalization` | `webauthn.registration.finalization.complete` |
| Recover completion | `/api/webauthn/register/recover-finalization-completion` | `recover-registration-finalization-completion` | `webauthn.registration.finalization.recover` |

The same suffixes are available under `/api/auth/session/webauthn/register/`.
Only those pending-session paths have an additional `/options` POST. All six
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
credential history requires a fresh action-bound WebAuthn assertion under the
current mutation policy and configured two-person approval. Genuinely empty
history requires fresh configured bootstrap, including development. Bootstrap
cannot replace existing-credential MFA. Identity and the history branch are
reread before dispatch, and the facade repeats genuine retained ownership under
the cold owner lock using authenticated user/session scalars, not a subject DTO.

The [pending-session permission flow](finalization-pending-permission.md)
requires explicit cookie CSRF, a fresh DB-time-valid pending session and current
RBAC. Empty history requires bootstrap. When the finalization's exact target is
the sole active credential owned by that user, fresh target-key assertion and
configured two-person approval can authorize completion without activating the
session. Foreign, revoked, extra or inconsistent credential history is denied.

Pending `/options` responses contain exactly `schema`, `purpose`, `localDigest`,
`action`, `resourceId`, `payloadDigest`, `publicKey`, and
`automaticRetryAllowed: false`, with schema
`serverware.webAuthnRegistrationFinalizationPermissionOptions/v1`. These are
actual server-generated action-bound options, not an accepted posted binding.
A 412/428 permission response preserves its actual action/resource/payload and
approval negotiation fields, without an automatic retry instruction. A 428 has
already consumed the assertion; explicit continuation requires another fresh
assertion. See the [portal flow](portal-registration-handoff.md).

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

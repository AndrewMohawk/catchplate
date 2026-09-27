# Public historical registration-completion recovery

Two API-only POST routes select historical completion recovery:

- `/api/webauthn/register/recover-completion` for the current operator.
- `/api/auth/session/webauthn/register/recover-completion` for a current pending
  OIDC first-enrollment session.

They use purpose `recover-registration-evidence-completion` and action
`webauthn.registration.execution.recover`. They do not execute or retry SQL,
finalize a credential, activate a pending session, or change existing live
execution/completion routes. No portal UI is added.

## Request and present permission

The closed body requires `purpose` and canonical SHA-256 `localDigest`, with
optional `bootstrapToken` and `mfa`. `mfa`, when present, permits only optional
`assertion` and `approvalId`; it cannot supply an actor, roots, expected hashes,
or a successful-verification result. Requests require exactly one canonical
positive `Content-Length`, `Content-Type: application/json`, no query string,
transfer/content encoding, or duplicate JSON members, and at most 64 KiB.

The handler requires the actual cold owner's SQL/completion handoff profile.
It authenticates the current operator or pending session, then genuinely
replays the retained historical registration subject before consuming fresh
permission. Its exact seven subject fields bind local record, user, challenge,
session, historical mode, request digest and operation identity. The separate
`serverware.webAuthnRegistrationCompletionRecoveryIntent/v1` adds the fixed
recovery purpose/action to the MFA and approval digest; historical enrollment
mode does not grant present recovery permission.

An operator with any credential history, including revoked credentials, needs
a fresh action-bound WebAuthn mutation assertion and configured two-person
approval. No-history enrollment requires the independently configured bootstrap
token, including in development; it cannot accept MFA instead. Conversely,
bootstrap cannot replace existing-credential authorization. Production startup
requires the recovery action in the two-person policy when this handoff profile
is enabled. Assertion verification precedes approval negotiation: a consumed
assertion must not be reused after a `428` response.

Pending-session recovery is first-enrollment-only, requires cookie CSRF even
when authorization headers exist, and requires the fresh bootstrap branch.
Both paths re-read current operator/session and credential-history state before
dispatch. The actual facade repeats user/session ownership admission. Credential
history on the pending-session path, session expiry/change, scope mismatch, or
missing cold configuration fails closed.

## Recovery and public result

The private recovery facade either authenticates retained acknowledged
completion originals or makes one explicit completion-recovery request and
authenticates its returned originals. Historical caller/planning/grant scope is
replayed; signed observations are not independently current database facts.
Recovery does not renew expired execution authority or infer the current
pending head from an acknowledgment. Prior uncertainty is not overwritten; a
separate immutable reconciliation record retains the recovery result.

Success is HTTP `202`, schema
`serverware.webAuthnRegistrationCompletionRecovery/v1`, status
`completion-recovered`, the fixed purpose and existing `localDigest`, with
`observationAuthenticated: true`. `registrationCompleted`,
`currentnessEstablished`, and `automaticRetryAllowed` remain `false`.

Internal failures return a redacted `503` detail with
`registration_completion_recovery_unavailable`, `remoteState: unknown`, the
same false completion/currentness/retry flags, and an optional local ID only
after actual subject inspection. No raw originals, packet selectors, signing
material, bootstrap/MFA values or internal exception text are returned.
Bounded public `4xx` authorization/approval negotiation remains available;
dictionary details remove the generic `retry` field and explicitly deny
automatic retry. Responses are non-cacheable. Cancellation is not converted
to an asserted outcome.

This is source-only and unexecuted, not deployment or full enrollment
acceptance. Independent cold provisioning, historical original retention,
completion/state authority and checkpoint admission remain prerequisites;
credential finalization remains separate. Planned frozen verification covers
strict framing, wrong owner/session/purpose, no-history versus history gates,
CSRF and stale approval/assertion/session rejection, authentic historical
recovery and conflicting retention, redacted uncertainty, and no SQL dispatch.

Source: [routes](../serverware/control_plane_registration_recovery_routes.py),
[HTTP contract](../serverware/control_plane_registration_recovery_http.py),
[historical planning history](historical-evidence-planning-history.md).

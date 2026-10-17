# Retained registration activation prerequisite

This source-only slice supplies local authenticated-original inspection for a
future, separately authorized OIDC activation transition. It is unbuilt and
unexecuted. It does not activate a session or add a public activation endpoint.

The [inspector](../catchplate/control_plane_registration_activation_subject.py)
exports:

```text
inspect_retained_registration_activation_subject(
    local_digest, *, expected_user_id, expected_session_id)
```

The locator is the retained finalization-grant ID. Expected user and nonempty
session must come from genuine present authentication, not posted identities.
The original mode must be `oidc-session-first-enrollment`, and the genuine
retained user/session must match those exact caller scalars.

## Original admission, never a stored success flag

Under the actual cold enrollment owner's PID, lock and readiness guards, the
inspector first repeats [retained completion ownership](control-plane-finalization-completion.md):
the complete finalization/evidence/signer association, original caller and grant
signatures, complete-vector transition replay, signer-regenerated full request
and inputs, associated evidence completion, and independently pinned pending
scope. The authenticated finalization request supplies the credential ID.

It then selects only an already retained finalization reconciliation or first
completion outcome. The record's source, finalization locator and fixed kind
must match the retained association. Missing or uncertain completion fails
locally. An `acknowledged` status is merely a structural prerequisite: the
[historical completion verifier](registration-finalization-history.md) actually
replays the original raw10, reserve raw3 and retained completion raw4 against
the current cold owner's independent configuration, enrollments and pending
sequence/head/fence. No posted successful-verification object is accepted.

The exact result is a fresh ordinary eight-field dictionary: `localDigest`,
`userId`, `challengeId`, `sessionId`, `mode`, `requestDigest`, `operationId` and
`credentialId`. The existing completion subject API is unchanged. No full
request, key material, signed original or reusable authority token is exported.

The private actual-owner method
`_inspect_retained_registration_activation_subject(..., live_window, transport_deadline_ns, work)`
allows a future fixed continuation to repeat this admission using its existing
current work and original window. It accepts a locator and authenticated
scalars, not this dictionary as proof. All retained original inventory and
processing bounds remain in force; no old expiry becomes a fresh permission.

## Deliberately absent effects and authority

This helper never calls completion or recovery transport, appends or reconciles
an outcome, signs, retries SQL, mutates a credential, or activates a session.
Here, local-only/no-network means no completion fetch, recovery or write;
reading retained custody originals may still use their existing fixed read
channel. It is not a promise that every underlying original read is local I/O.
If completion is absent or uncertain, the user must use the independently
authorized [completion/recovery path](public-registration-finalization-completion.md);
inspection does not dispatch it automatically.

Authenticated history does not prove that the credential remains active or
that the pending cookie, roles, trust policy and session state remain valid.
Separate fresh activation permission and authoritative current state checks,
protected activation execution, token/delivery contracts and outcome handling
remain F08 work. This prerequisite does not close F08 or export a verified
subject capability.
The existing registration finalization transition inserts a credential and
consumes evidence/challenges; it does not update `oidc_browser_sessions`.
No scalar acknowledgment authorizes a replacement session or inherited login.

Only the independently configured historical cohort is supported. Independent
cross-generation authority, external currentness and production provisioning/
verification remain separate. No activation, current-head or release claim is
made by the returned dictionary.

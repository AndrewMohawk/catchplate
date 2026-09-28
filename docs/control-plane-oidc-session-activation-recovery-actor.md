# Fresh recovery actor for the original session

Source only, unbuilt and unexecuted. This slice provides genuine recovery
options and a private live authorization context. It does **not** dispatch
recovery, retry activation SQL, release a token or confirm a session. Step 23
remains incomplete until its separately authorized recovery owner is connected.

## Actor and target are separate

Protected activation can replace the pending session's token digest before
its HTTP response arrives. The old cookie therefore may no longer authenticate
through the normal OIDC session lookup. Repeating login would create another
session and overwrite that cookie; it would not authenticate the original
target. This path creates no new OIDC flow or recovery cookie.

The actual old cookie supplies exactly 64 bytes of possession evidence, never
an actor ID. Every options or private authorization call freshly invokes the
historical recovery inspector. Genuine retained finalization/acknowledgment
and root-enrolled signed intent bind the original user, session and credential;
the old bytes must match the original token commitment. Browser-supplied target
graphs, signed originals and previously successful inspector objects are not
accepted. A local activation authorization digest is only a retained-record
association locator, not proof that activation executed.

The actor freshly reads the exact `(user_id, session_id)` target, never a
permissive old-token alias. That read-only query rejects expired/revoked rows
and requires an explicit live provider expiry. Pending targets must still be
unbound and retain the old digest; active targets must retain the authenticated
new digest and original credential record. Active target checks reuse the
genuine current session/trust checks but do not replace fresh actor proof.
An expired, revoked, replaced or differently bound target is not revived.

## Current actor proof and policy

The actual retained user's RBAC binding must exist, be active and grant admin
or approver. There is no development claimed-role fallback. Current credential
history must contain exactly the original sole nonrevoked credential. The
genuine authenticator-policy helper checks current trust and permitted classes
under the actual trust lock; the policy always requires user verification.

Options use the existing genuine mutation-options producer and return only its
single exact target-key challenge. The distinct action is
`webauthn.oidc-session.activation.recover`; its payload digest binds the
retained target and old-token commitment. Options consume no assertion and
are neither permission nor a recovery result.

The private authorizer verifies a fresh assertion for that exact action,
challenge and digest, checks the actual credential record/counter and performs
the existing challenge claim and authenticator counter CAS. It then invokes
the configured two-person approval path with the same action and target.
Permission-side challenge, counter or approval effects are not activation SQL
and are not undone or retried after a refusal.

The default two-person action list now includes recovery and its requester-role
classification explicitly permits approver, like activation authorization.
**Configuration migration:** installations explicitly setting
`SERVERWARE_CONTROL_PLANE_TWO_PERSON_ACTIONS` must add
`webauthn.oidc-session.activation.recover` or `*` when global two-person approval
is enabled. An old explicit list does not inherit the new default: options and
authorization fail closed until this action is covered. No secret configuration
is read or rewritten by this source change.

## Live context, not a permission carrier

`_authorize_on_owner(...)` is a private context manager for the future recovery
owner. It accepts the actual Request/original body and original owner/work/time
bounds, acquires the actual startup/trust locks, and freshly admits historical
evidence and actor proof. Its source-constructed scope is invalid after exit;
no public endpoint returns or accepts it. A source-owned latch rejects nested
or overlapping recovery scopes and any live activation permission.

Current guards retain original PID/thread, owner/resources, Request/body,
Origin/CSRF/cookie, policy, RBAC, credential, trust and target-row snapshots.
Original clock floors and delivery expiry stay attached; current session and
provider expiry can only shorten the same allowance. Guard callbacks do not
reload the journal or reopen historical admission. The old token stays in
request/live-scope memory only, never journal, logs or JSON.

The [options route](control-plane-oidc-session-activation-recovery-routes.md)
is the only public addition. Recovery effects, outcome inspection, guarded
token delivery, portal wiring and runtime/provisioning evidence remain open.

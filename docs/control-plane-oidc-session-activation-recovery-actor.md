# Fresh recovery actor for the original session

Source only, unbuilt and unexecuted. Genuine recovery options and the private
live actor context now connect to same-context recovery grant acquisition,
one-shot recovery-worker staging and a separate private protected-exchange
context. The separately selected terminal path retains explicit normal-cleanup
evidence; the actor itself does **not** prove worker readiness, repeat activation
SQL, deliver a browser cookie or confirm a session. Step 23 remains incomplete.

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
`CATCHPLATE_CONTROL_PLANE_TWO_PERSON_ACTIONS` must add
`webauthn.oidc-session.activation.recover` or `*` when global two-person approval
is enabled. An old explicit list does not inherit the new default: options and
authorization fail closed until this action is covered. No secret configuration
is read or rewritten by this source change.

## Live context, not a permission carrier

`_authorize_on_owner(...)` is a private context manager consumed by the actual
[recovery acquisition owner](control-plane-oidc-session-activation-recovery-acquisition.md).
It accepts the actual Request/original body and original owner/work/time
bounds, acquires the actual startup/trust locks, and freshly admits historical
evidence and actor proof. Its source-constructed scope is invalid after exit;
no public endpoint returns or accepts it. A source-owned latch rejects nested
or overlapping recovery scopes and any live activation permission.

Each actor initializes `_recovery_acquisition_spent=False` once. The actual
acquisition owner spends it only after genuine actor authorization, and neither
failure nor scope cleanup resets it. The parent's private
`_acquire_oidc_session_activation_recovery_grants(...)` facade returns that
context manager with the exact Request/body/work/window/deadline/current args;
it creates no work or time allowance and does not close the global owner.
Within the same active context, acquisition re-admits the independent recovery
policy, durably claims its exact policy-keyed attempt, calls the finite private
client, and retains exact returned raw3 originals with genuine current guards.
Before yielding, it stages only its retained server original through the fixed
root receiver. The local staging latch is spent before contact; a matched ACK
is not readiness, private-store evidence or permission to repeat the operation.
Leaving the context invalidates access; retained bytes do not become a reusable
permission carrier or retry authority.

The separate private recovery facade enters this same acquisition context,
spends a distinct exchange latch, and delegates to the genuine
[protected exchange](control-plane-oidc-session-activation-recovery-exchange.md).
Token access requires the actual retained receiving guard while the actor is
still live. Response children are excluded from their own ancestor callbacks;
cleanup invalidates the accessor and live guards. The ordinary private path is
not a public success endpoint or an authorization to send after context exit.

The separate [recovery delivery terminal](control-plane-oidc-session-activation-recovery-delivery.md)
must be selected before exchange derivation to retain genuine original
ancestors and the final receiver's exact restrictions. This actor is never
reactivated for that suffix. Its `_normal_exit` starts False and is cleared by
`_close`; only the normal authorizer return sets it True, after the final current
guard, normal trust-context exit, final source guard, actor close and successful
startup-lock release. The enclosing acquisition sets its own normal-exit marker
only after that complete actor suffix. A finally-closed object or a copied token
is not evidence of successful cleanup. Any failed suffix keeps the relevant
marker False, while the one-use acquisition latch remains spent.

The terminal separately joins those markers and exact original identities
before post-cleanup current-auth/cookie delivery. The actor's `_guard()` and
`current()` still require the actual active scope; there is no closed-actor
fallback, fresh work allowance or relaxed PID/thread check.

Current guards retain original PID/thread, owner/resources, Request/body,
Origin/CSRF/cookie, policy, RBAC, credential, trust and target-row snapshots.
Original clock floors and delivery expiry stay attached; current session and
provider expiry can only shorten the same allowance. Guard callbacks do not
reload the journal or reopen historical admission. The old token stays in
request/live-scope memory only, never journal, logs or JSON.

Before historical target replay, a fixed source-selected graph measurement
reserves the held request, payload, policy, pins and original scope bytes.
Key representations use fixed byte reservations without key-object traversal.
The history inspector adds its token and independent intent inputs before
calling the [combined historical reader](control-plane-registration-finalization-completion-history.md).
It preflights all selected metadata before any body read, replacing the earlier
post-load aggregate check. These are source-defined representation bounds, not
a full-call 64 MiB process-heap guarantee or runtime evidence.

The [public route contract](control-plane-oidc-session-activation-recovery-routes.md)
and separate terminal/HTTP integration own the public delivery boundary. The
[source-connected worker handoff](oidc-session-activation-release-recovery-dynamic-delivery.md)
does not demonstrate actual retained outcome-store behavior. Private token
exchange is source-connected; earlier-stage completion recovery, portal wiring
and runtime/provisioning evidence remain open.

# Completion recovery retained-outcome delivery

This .214 source-only path connects separately reconciled consume completion to
a distinct fresh `retained-release` action and independently authorized
RECOVERY/checkpoint-one delivery. It is not an automatic fallback, retry or
profile switch by the [LIVE first-release action](control-plane-oidc-session-activation-completion-recovery-delivery.md).
The existing normal post-intent RECOVERY path is unchanged. Source integration
is not observed token delivery, worker readiness or production acceptance.

## Separate public purpose and original allowance

The fixed POST action is
`/api/auth/session/activation/consume/completion/recovery/retained-release`;
its options route adds `/options`. The [fresh actor](control-plane-oidc-session-activation-completion-recovery-actor.md)
uses `catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryIntent/v1`
and the distinct `retained-release` purpose. Preparation-only approval, closed
actors and prior LIVE permissions cannot authorize this action.

The original bounded 64 KiB carrier supplies no browser-selected target, grant,
root authority or token. Genuine historical target/old-cookie possession,
current sole-credential checks, WebAuthn, RBAC/trust, Origin/CSRF and configured
approval remain required. The HTTP core opens one work/window before parsing or
owner I/O. Every child only narrows that allowance; original delivery expiry
remains a hard ceiling. The asynchronous route calls the bounded synchronous
core on the same ASGI thread, not a nonblocking-I/O or concurrency guarantee.

The actual private owner facade enters the coordinator's `_recover_on_owner`
context. It does not accept a caller-supplied successful actor or permission DTO.
The [historical controls](control-plane-oidc-session-activation-completion-recovery-controls.md)
select genuine original completion/hints raw6 or the exact separate immutable
consume reconciliation raw6. No old uncertain outcome is overwritten; a
reconciliation attempt without a usable response does not reopen its socket.
Retained intent and proof are genuinely re-admitted read-only: no new intent
signing, setup, proof request, completion exchange or SQL execution occurs here.

## Policy claim, opaque retention and independent admission

The [acquisition coordinator](../catchplate/control_plane_oidc_session_activation_completion_recovery_retained_acquisition.py)
uses independently configured recovery issuer endpoint, policy, custody and
enrollment originals. It re-admits the policy and joins its expected release,
evidence, proof scope and caller to the actual retained originals before contact.
It never learns its expected authority from returned grants.

The [guarded custody methods](control-plane-oidc-session-activation-completion-recovery-release-records.md)
share the existing policy slot keyed by finalization, activation authorization,
release-intent and issuer-policy identities. An existing claim from either the
normal or new path refuses reacquisition. A new irreversible claim is published
before the sole issuer exchange; a lost reply remains terminal for that policy.
The first bounded raw3—client authorization, server bootstrap and outcome
original—is durably stored as opaque DATA before genuine triple admission.
No request, cookie, old token or returned token enters these records.

The fixed issuer wire permits no error/status substitute, retry or renewed
clock. Its aggregate response cap is 128 KiB before body allocation. The genuine
triple verifier independently re-derives and authenticates the expected scope,
signatures, profile, resource pins, request identity and original outcome binding
under the same work and narrowed lifetime. A reconstructed canonical outcome
is an expected identity, not proof that the private store contains it.

## Exact worker staging and protected RECOVERY

Only the active acquisition owner stages its own admitted server original. The
staging latch is spent before contact with the fixed recovery-bootstrap socket.
The wire ceiling is 16 MiB for that server original; this action's already tighter
128 KiB raw3 cap also applies. The exact bootstrap-identity ACK and normal close
are required before the active context proceeds. An ACK is not worker readiness,
private-store existence or successful release.

The existing recovery-only receiving owner independently admits the root policy
and staged original, binds the actual resources, and continues through same-PID
privilege drop into the finite worker. No private signer or AES key is delivered
to the public caller.

The [protected exchange](../catchplate/control_plane_oidc_session_activation_completion_recovery_retained_exchange.py)
re-admits the genuine originals under fixed RECOVERY/checkpoint-one authority.
The protected endpoint comes from that policy, not the issuer endpoint or a LIVE
pin. Before the sole socket exchange it durably claims the **same global client
authorization slot** used by other release paths. Every existing claim refuses.
The worker must verify the actual retained private outcome against its independent
checkpoint-one pins; local record absence and reconstructed bytes cannot replace
that verification. There is no new-outcome append, repeated SQL, automatic retry
or expiry renewal. Genuine response admission follows normal socket close and
retains its full narrowed guard separately from its ancestors.

## Current-auth, cleanup and signed cookie sending

The [terminal response owner](control-plane-oidc-session-activation-completion-recovery-delivery-response.md)
is selected before receiving, not wrapped around a copied token after cleanup.
It performs fresh token-based current-auth and exact target matching, stages the
fixed nonsecret response and one cookie, then requires normal actor and context
cleanup before `.finish()`. The signed ASGI send boundary retains the original
resource/receiver guards and checks the exact body and cookie again.

Success uses `catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryResponse/v1`,
purpose `retained-release`, status `recovered`, session state `active`, and no
automatic retry. No token or permission DTO crosses the HTTP coordinator.
Pre-send failure preserves the existing cookie. After headers start there is no
undo, second response or delivery guarantee; external output may be uncertain.

## Capacity and remaining scope

A fixed additional 16 MiB representation lane is reserved before the first
historical body read **inside**, not in addition to, the original 64 MiB ceiling.
It covers acquisition, guarded persistence, admission, staging, exchange and
terminal headroom. Custody operations receive a tightening 2 MiB cap, reserve
selected immutable encoded sizes plus publication/metadata before body one, and
charge the original work directly. The global dispatch claim has its separately
reserved fixed bound. Large otherwise valid inputs can refuse; these bounds are
not heap, RSS or runtime measurements.

COMPLETE and step 23 remain partial. Unattempted-consume continuation, portal
actions and external resources/provisioning/full production acceptance remain
open. Project 34/46, activation 22/26 and production 0/6 are unchanged. This source
is unbuilt, unexecuted and unprovisioned; no test, deployed delivery or production
gate closure is claimed.

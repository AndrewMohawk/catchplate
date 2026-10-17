# Fresh actor for earlier completion recovery

The private completion-recovery actor joins the independently configured
parent-v16 completion lane to genuine pre-intent target history and fresh
WebAuthn permission. It is a distinct exact type, not a renewed activation
permission or an intent-stage token-recovery context. Source only: unbuilt,
unexecuted and unprovisioned.

## Archived completion expectations, current permission

Parent v20's [activation history v2](control-plane-oidc-session-activation-history-bootstrap.md)
adds independently archived completion expectations. The genuine historical
target now retains its selected authority. Before WebAuthn options or assertion
binding, the actor combines the currently enabled phase endpoint with that
authority's exact packet, authorization and pending tuple. An archived endpoint
never authorizes current contact; an absent archived completion lane fails closed.

The original current configuration and effective historical expectation scope
are separately retained and checked on each guard. The actual target/authority
identity and archive guard survive through completion receiving and normal
cleanup. An additional 16 KiB metadata reservation is held before the first
historical body; later receiving/publication headroom is passed into that same
target allowance, not added as a new budget after reading.

This connection is completion-only. Non-completion purposes explicitly require
the genuine current-mode configuration/root/execution/planning/consume/intent
material identities before options or authorization. Matching-looking archived
pins are insufficient to reach a current-key producer. The existing no-history
path preserves exact current objects; historical fresh consume, intent/proof,
grant and release need their own joins and remain H05 work.

## Source-selected purpose and target

The actual enrollment owner has separate activation and consume completion
options/authorization methods. Each selects a literal profile internally; the
closed HTTP request carrier accepts only its existing locator and optional MFA
data, never a completion profile, target, root policy, packet or grant.
Both lanes require an actual independently admitted
[completion-recovery configuration](control-plane-oidc-session-activation-completion-recovery-bootstrap.md).
Disabled or older parent profiles do not silently enable recovery.

The [historical inspector](control-plane-oidc-session-activation-completion-recovery-history.md)
authenticates retained plan/caller originals, independently reconstructed
expectations, genuine finalization target/ACK and actual old-cookie possession.
It derives signed old/new token commitments and the exact credential record
without fabricating a release intent, delivery identity or delivery interval.
The activation lane additionally matches the independent caller authorization
digest. The consume lane additionally uses the separate
[historical controls join](control-plane-oidc-session-activation-completion-recovery-controls.md)
before any completion request; fresh actor admission alone does not prove
that association or any committed effect.

The assertion binding uses a distinct completion-recovery intent schema. It
includes the exact subject, historical activation authorization and challenge,
old-token commitment, source-selected completion profile and independently
pinned completion authorization, packet and pending scope. Existing recovery
approval policy still applies to this recovery-only action. A token-recovery
challenge or another profile's assertion cannot substitute for this different
payload digest.

The consume lane also supports the source-fixed `release-intent-proof` purpose
through distinct options/action facades. It uses a different binding schema and
includes that purpose in the WebAuthn/approval payload; completion-only approval
cannot authorize signing or proof acquisition. Its exact fixed route is checked
before actor construction. Future intent/proof and reconciliation capacities are
reserved before the first target body and carried forward once, not granted as
a second budget. The existing completion coordinator rejects this new purpose.

The source-fixed `release` purpose is separate again. `DELIVERY_PATH` selects
only `POST /api/auth/session/activation/consume/completion/recovery/release`
and its `/options` action, with no query string and only the consume profile.
`DELIVERY_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryDeliveryIntent/v1`;
`DELIVERY_OPTIONS_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryDeliveryOptions/v1`.
Its assertion/approval binding includes `recoveryPurpose: release`, so neither
a completion assertion nor a `release-intent-proof` preparation assertion can
substitute for the fresh release authorization. The exact purpose remains pinned
through every guard and cleanup. Preparation permission is never broadened, and
its closed actor is never reused.

The separate source-fixed `retained-release` purpose selects only
`POST /api/auth/session/activation/consume/completion/recovery/retained-release`
and its `/options` action. `RETAINED_DELIVERY_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryIntent/v1`;
`RETAINED_DELIVERY_OPTIONS_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryRetainedDeliveryOptions/v1`.
The signed assertion/approval binding includes `recoveryPurpose: retained-release`.
Neither a LIVE `release` assertion nor preparation permission can select this
action, and a failed LIVE request cannot switch to it automatically. Independently
root-admitted RECOVERY/checkpoint-one originals remain necessary; an absent local
record or reconstructed outcome is not private-store evidence.

All three consume release purposes require actual parent intent/proof configuration and use
the same genuine historical target, old-possession check, fresh session/key/trust
admission and original future-reservation accounting. A release actor is an
authorization prerequisite only: these actor changes add no release checkpoint,
grant selection, socket exchange, private store read or cookie effect. Any such
continuation must independently admit its original release authority while this
new actor is live; the existing private acquisition API remains exact-type
incompatible.

The distinct source-fixed `consume` purpose instead requires the **activation**
profile and exact path
`/api/auth/session/activation/completion/recovery/consume` (or `/options` for
the private challenge API). `CONSUME_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryConsumeIntent/v1` and
`CONSUME_OPTIONS_SCHEMA` is
`catchplate.oidcSessionActivationCompletionRecoveryConsumeOptions/v1`.
The binding includes `recoveryPurpose: consume`; completion, preparation and
release assertions cannot substitute. It authorizes only the future same-call
consume continuation after genuinely acknowledged activation. It never permits
activation SQL retry, old execution renewal or an `_ActivationPermission`
substitute. The [original-only extractor](control-plane-oidc-session-activation-completion-recovery-consume-inputs.md)
feeds the independent consume-input issuer under this actual fresh owner.
This source slice adds no public consume options/action route or success HTTP;
protected consume completion must be connected first.

## Current checks and lifecycle

The actor reuses the existing sole-credential, current trust, explicit RBAC and
exact target-session checks. A pending target must still have the original old
token commitment and no bound credential; an active target must have the signed
new token commitment and original credential. Neither state establishes SQL
completion or authenticates the actor. The real fresh assertion must verify
the exact key and authenticator counter, followed by configured independent
approval. Current provider/session expiry only narrows the same processing
window; historical execution intervals are never renewed.

Request/Origin/CSRF/cookie, policy, target and configuration snapshots remain
fixed. The same work, owner/resource ancestors, PID/thread, clock floors and
startup/trust locks surround every live check. Already held request/config/key
representations reduce the inspector's available capacity before body reads.
No parser result, signature-shaped object or retained metadata is permission.

Options return only a real target-bound challenge. Authorization yields only
inside the live context. Final guards and normal trust/startup-lock cleanup
precede a normal-exit marker; cleanup revokes the actor and clears old-token
access. The ordinary actor remains closed and cannot supply a post-cleanup guard.
Only the separate [source-owned release terminal](control-plane-oidc-session-activation-completion-recovery-delivery-response.md),
selected before the new genuine LIVE or RECOVERY receiving chain, can retain the final receiver across
known successful normal cleanup using captured independent original ancestors.
It does not revive this actor or broaden preparation permission. The ordinary
intent-stage actor and exact-type token-acquisition entrypoint remain distinct.

## Still required

The actor itself does not contact a service. Its actual
[completion-only coordinator and public routes](control-plane-oidc-session-activation-completion-recovery.md)
now join historical public controls, one durable attempt, independently selected
exchange, genuine response checks and separately retained reconciliation.
The receiving child is checked separately after the action and normal trust
cleanup, never called by its own actor ancestor. No closed-actor fallback exists.
Private AES/history replay stays in the isolated completion service.

The separate [fresh intent/proof coordinator](control-plane-oidc-session-activation-completion-recovery-release.md)
now uses this distinct purpose for retained acknowledged consume originals.
The two fixed release actions use independently admitted release-profile/checkpoint
and guarded current-auth/cookie continuations; the actor alone establishes neither.
Missing evidence is unavailable
or unknown, not SQL nonexecution, private-outcome absence or retry authority.
COMPLETE and activation step 23 remain incomplete; these actor methods and the
completion-only response establish no cookie, active session or production claim.

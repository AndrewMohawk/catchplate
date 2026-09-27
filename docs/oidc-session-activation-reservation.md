# Activation reservation and independent pending admission

This is source implementation, not built, executed, provisioned or production
verification. It composes the actual dedicated
[post-plan caller authorization](oidc-session-activation-execution-authorization.md),
original execution grant and private encrypted activation originals. It does
not execute SQL, complete activation, release a token or establish a session.

## Signed reserve and original response

`authority_oidc_session_activation_reservation._produce_on_work` receives only
original signed caller/grant/enrollment bytes, activation raw2 (signed plan and
encrypted execution bundle), closed original expectations, the independently
held complete before-vector and configured keys/configuration digest. The
actual receiving custody must have the fixed `reserve` purpose. Independent
predecessor sequence, predecessor head and fence precede computation signing.

The caller authorization is genuinely verified and bound to the plan, raw2,
request, operation, journal and complete before-vector. Actual grant controls
are verified against that authorization; grant expiry cannot extend caller
expiry. Activation's authorization is intentionally post-plan: the grant and
reserve retain the original plan issue time, without backdating the caller.
The actual generic reserve producer performs complete private plan replay and
returns its genuine `CurrentRootComputation` request/snapshot originals. No
caller-supplied replay result or successful authority carrier is admitted.

`_verify_response_on_work` takes the same originals, independent predecessor
scope and returned raw3 (signed reserve, exact snapshot, signed state ACK).
It genuinely replays the grant/private plan, verifies the live computation
request, compares exact before/after vectors and reconstructs the snapshot.
The fixed activation record verifier additionally authenticates the original
state receipt and all request/scope joins. Only unchanged raw3 is returned.

A private `_verify_retained_on_work` path permits a missing receipt solely to
replay an already retained reserve/snapshot before explicit delivery. It does
not sign a replacement or treat missing acknowledgment as permission to retry.
Every path retains the supplied work, original clock bracket, inherited
deadline and caller/grant liveness, including after native process/key checks.
Original reserve expiry only shortens subsequent state exchange and response.

An authentic ACK establishes the signed reservation event, **not** an
independently current pending head. The head is never adopted from that ACK as
its own expected value.

## Separate current-pending boundary

`authority_oidc_session_activation_pending_admission._admit_on_work` takes the
same original authority and raw3, plus independently held database identity,
generation digest, pending sequence, pending head and fence. It also joins
independent predecessor pins; the supplied pending sequence must be predecessor
plus one. The actual private receiving owner must have `sql-issuer` purpose.

The real generic successor admission authenticates the computation and state
receipt against those independent pins, replays the original private plan and
joins the original grant and snapshot. The wrapper checks the original caller
authority, before-vector and nonrenewed interval through return. It returns
unchanged raw3, not mutations or a token a downstream issuer may trust instead
of its own actual replay.

This receiving API is source implemented but is **not connected to an actual
cold SQL-issuer consumer in this batch**. The reserver cannot provide the
future independently current pending scope. That connection, protected SQL,
completion/reconciliation and protected token delivery remain separate work;
the reservation/pending parent checkpoint remains partial.

## Durable service boundary

The dedicated [reserver service](oidc-session-activation-execution-reserver-service.md)
uses root-admitted reserve custody and a separate private journal. Its
[record and delivery profile](oidc-session-activation-reservation-delivery.md)
retains exact request/snapshot before the state exchange and the genuine ACK
before response. The [transport](oidc-session-activation-reservation-transport.md)
is raw5 to raw3 with a whole-exchange 64 MiB cap, not a plaintext token channel.
The [cold bootstrap](oidc-session-activation-execution-reserver-bootstrap.md)
holds predecessor and local journal checkpoint independently. Neither local
retention nor a static predecessor proves current off-host state. State v5's
fixed operation/action gate still performs the actual atomic comparison.

No automatic resend, refreshed clock, historical execution authority, public
activation endpoint, browser state claim or provisioning is added here.

# Public fresh consume after recovered activation

Two fixed POST paths use the existing bounded recovery framing and error routing:

- `/api/auth/session/activation/completion/recovery/consume/options`
- `/api/auth/session/activation/completion/recovery/consume`

The first creates fresh WebAuthn options for the exact activation-profile actor
with purpose `consume`. The second enters the actual private
[`_ConsumeAttempt` workflow](control-plane-oidc-session-activation-completion-recovery-consume.md),
under a distinct fresh assertion and independent consume configuration. JSON
cannot select another purpose, profile, endpoint, key or execution authority.
Neither route revives `_ActivationPermission`, retries activation SQL, or treats
missing journal evidence as proof that consume was never attempted.

The existing middleware bounds the original request before accumulation and
requires the literal POST path, no query/transfer/content encoding, exact JSON
content type and one bounded content length. The core accepts only the exact
immutable bytes retained on that actual request. Existing Origin/CSRF framing
and the actor's fresh current-target, WebAuthn, trust, RBAC and approval checks
remain required; options are not execution permission.

Each request opens one work ledger and original live window. The two startup
facades forward those original arguments unchanged. Async route functions call
the bounded synchronous core directly on the ASGI thread, preserving its
thread-bound locks and guards. This deliberately blocks that thread during the
bounded operation; it is not a high-concurrency or runtime-readiness claim.

The action marks its outcome uncertain before entering the actor/consume
context: authentication, issuer, reservation or SQL effects can happen before
the context yields. The existing durable consume slot and pre-SQL claim govern
one-use effects. Raw responses remain data until their genuine admission, and
unknown effects never authorize an automatic retry or alternate profile.

Inside the actual context, the source-owned consume terminal stages only the
acknowledged completion observation. Its `finish()` is called after normal
context exit and requires the actor and consume owner's successful cleanup
markers. A failure during entry, verification, cleanup or finishing returns
fixed `consume-outcome-unknown` data with HTTP 503. Pre-entry rejection uses
fixed bounded errors without exception text. Neither path returns retained
originals, a token, key material or a success authority object.

Success is `consume-completion-acknowledged`, with `sessionState: unknown`,
`tokenReleased: false` and `automaticRetryAllowed: false`. No cookie is set,
deleted or replaced. This is a historical completion observation, not current
session success or permission to release a token. A later independently
authorized release/current-auth/cookie boundary remains separate.

The original only-narrowing lifetime and 64 MiB representation ceiling remain
unchanged. The 16 KiB terminal-response reservation is included before the first
historical target read, inside that ceiling rather than as a new allowance.
Source only: unbuilt, unexecuted and unprovisioned. Portal, other unfinished
project work and all independent deployment and production acceptance gates
remain open.

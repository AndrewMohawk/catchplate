# Authorized finalization plan admission

[`authority_registration_finalization_plan_admission.py`](../catchplate/authority_registration_finalization_plan_admission.py)
connects the distinct original finalization authorization to a genuinely verified
**new** finalization custody raw7. This is source-only, unbuilt and unexecuted;
it is not credential execution or production admission.

The private `_verify_on_configuration` takes independently admitted
`payload`, `configuration_digest`, `generation`, `runtime_role_identities`,
exact raw7 `originals`, `authorization_bytes`,
`authorization_enrollment_bytes`, `grant_enrollment_bytes`,
`current_root_enrollment_bytes`, actual `root_public_key`, and the caller's
existing `live_window`, `work` and optional `transport_deadline_ns`.
It returns only those unchanged seven originals. No successful-verification
object, request digest, history, clock or key fallback is accepted instead.

## Original authorization before new planning

The fixed operation is `webauthn.registration.finalize`; the original caller
purpose is `authorize-registration-finalization`. The actual finalization
transition-policy mapper supplies the planner key, operation evidence key,
verifier key, generation, policy limits and identities. Evidence-admission
authorization or an evidence-only policy mapper cannot substitute for them.

The root-enrolled caller signature and actual enrollment/key separation are
verified before custody replay. Raw7 is the intent, relay, plan envelope, proof,
inputs, evaluation context and separately committed historical expectations.
The actual custody verifier authenticates both controls and all original byte
commitments, joins independent configured pins and genuinely replays raw4.
Only then are the authenticated history's typed request digest and operation ID
recomputed and compared with the genuine caller authorization.

The original plan issue must be at or after authorization issue, and its expiry
must not exceed authorization expiry. The caller must therefore authorize
**before** making the new plan. This helper does not promote a previously
prepared finalization by replacing timestamps, obtaining a later signature or
accepting a copied successful result.

## Bounds and remaining authority

The complete original raw7, authorization and three enrollments must fit the
existing 64 MiB aggregate before native callbacks; individual source limits
remain mandatory. Configuration graphs are owned before callbacks. All phases
use the supplied cumulative work, opening clock bracket and inherited deadline.
Original caller, custody and plan intervals only narrow them. Existing inner
custody verifiers retain their own original-control checks; these do not renew
the surrounding processing deadline. Checks around synchronous work are not a
hard watchdog.

A private sibling continuation carries same-call facts to
[grant production](registration-finalization-grant-production.md); no exposed
entrypoint accepts those facts as authority. Neither API supplies present-user
permission, a new cold owner, transport, storage, current-root reservation, SQL,
completion or OIDC browser-session activation. The existing
[retained preparation](retained-registration-finalization.md) remains a separate
local-locator-only path; genuine finalization execution still requires its own
authority and outcome handling.

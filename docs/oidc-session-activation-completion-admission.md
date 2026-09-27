# Historical activation pending-completion admission

This private source adapter joins genuine historical activation originals to
an independently supplied pending checkpoint. It does not execute effects,
observe a database commit, sign completion, publish state or release a token.
Generic activation completion remains rejected; no build, test, runtime or
provisioning evidence is claimed.

## Originals and independent scope

[`authority_oidc_session_activation_completion_admission`](../serverware/authority_oidc_session_activation_completion_admission.py)
exposes the fixed-operation `_admit_on_work`. Inputs are the exact signed plan
and encrypted bundle (raw2), closed request/scope/journal expectations, original
caller authorization and caller/grant/current-root enrollments, original grant,
reserve/snapshot/ACK, independently admitted keys/configuration and exact
database/generation/pending-sequence/head/fence, plus the actual historical
custody owner and supplied current work/window/deadline. No successful replay,
candidate, caller-selected clock or alleged current head is accepted.

The adapter owns external graphs and original references before callbacks and
enforces the existing per-frame and 64 MiB aggregate bounds. It verifies the
root enrollment, original signed reserve and signed ACK using the real control
helpers. The independent pending pins must match the receipt, fence and exact
reserve identity, including its signed predecessor and reserved completion
capacity. The ACK does not establish those independent pins.

The exact historical custody owner independently binds root/enrollment and the
signed reserve's before-vector to its root-pinned complete vector. Its genuine
[historical exchange](oidc-session-activation-historical-exchange.md) verifies
caller/grant signatures and raw2 originals, reconstructing the original six
effects and complete after-roots once. Existing computation helpers rebuild
the exact canonical snapshot; original reserve/ACK vectors and every grant
claim must match it. The reserve capability is the actual signed grant's
identity, not a receipt-derived authorization claim.

## Non-executable result and two time obligations

The private `_AdmittedCompletion` contains only `candidate`, `effects_digest`,
`authorization_digest` and `live`. Its actual `_PendingCompletion` candidate
contains the exact marker expectation, after-vector, reserve/snapshot/ACK and
original reserve interval. The effects identity is computed from this call's
genuinely reconstructed rows/mutations/result/work units, but none of those
executable effects is returned. The consuming completion composition must
independently join the authorization digest and observe actual immutable
custody/commit records before any enrolled completion signature.

The reserve retains the original plan issue time and cannot outlive its plan
or grant; the historical exchange separately bounds the post-plan caller and
grant to the original plan. These are algebraic checks on authenticated
originals, not fresh execution permission. Current processing uses the same
supplied real window, cumulative work and positive inherited deadline, with
sticky guards across control verification, private replay, snapshot/effects
binding and return. `live()` retains the actual owner and processing guards;
it does not compare the current time to an expired execution interval or renew
that interval.

This is strict current-source/configuration/key-cohort admission, not H05
cross-version historical authority or lost-original recovery. Cold role
delivery, real readers, completion signing, durable publication/reconciliation
and token delivery remain separate integrations. No generic rejection is
removed, no SQL is repeated and no successful result becomes an input proof.

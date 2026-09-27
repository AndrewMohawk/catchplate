# Historical activation originals and grant exchange

This is source-only prerequisite work for completion/reconciliation, not a
completed activation or a production result. Current source is unbuilt and
unexecuted. Generic activation completion still rejects requests until a
separately admitted historical custody and completion path exists.

## Authenticate originals, not a returned success object

The new private
[`authority_oidc_session_activation_execution_history`](../serverware/authority_oidc_session_activation_execution_history.py)
receives the real signed plan and encrypted bundle (raw2), independently
expected request/scope/journal digest, complete before-vector, planner/state
keys and state enrollment, distinct bundle/delivery AES keys, and an existing
current work/window/deadline. It accepts no previous plan or admission result.

The original known plan is genuinely authenticated before AES opening. Its
request, configuration, planner identity/key, positive original lifetime and
scope deadline must match the independently supplied expectations. Future
issuance is checked against the actual current clock with the original scope
skew; an old issue time is never substituted as the processing clock.

Actual bundle AEAD binds the source/configuration/request/plan/journal context.
The decrypted original must repeat the exact signed plan, enrollment and
complete vector, not alternative originals. The retained UTC database cutoff,
assertion, old/new tokens, delivery envelope, primary/query/write proofs and
thirteen heads reach the genuine [historical full-plan verifier](oidc-session-activation-historical-plan.md).
It repeats original [state admission](oidc-session-activation-historical-state.md),
[assertion/delivery semantics](oidc-session-activation-historical-semantics.md),
full six-effect derivation and indexed after-root reconstruction.

The complete vector merge compares all selected predecessor roots/heads and
updates only genuinely derived descriptors; unrelated descriptors stay intact.
The source delta validator checks both full vectors again. Returned private
historical facts include exact raw2 and original plan interval, derived effects,
full vectors and their identities, plus a current-only processing guard.
They do not serialize the private originals or AES keys into packets, release
a token, create a live replay result or become accepted authority inputs.

## Original caller and execution grant

[`authority_oidc_session_activation_history_exchange`](../serverware/authority_oidc_session_activation_history_exchange.py)
composes those originals with actual caller authorization, execution grant and
independently supplied caller/grant/current-root enrollments. All external
graphs, immutable bytes and keys are held before signature/decryption callbacks.
Per-frame and aggregate original bounds and the same work budget apply.

The distinct historical caller verifier uses the original root-admitted caller
purpose/key, signature and exact plan/raw2/journal/before-vector commitments.
Its authorization must remain inside the original plan interval:
`plan issued <= caller issued < caller expires <= plan expires`.
The actual original grant is authenticated before private-bundle replay. After
full replay, every grant claim is compared with genuinely reconstructed raw2,
request, result, plan, effects/vector commitments and original interval. The
grant's issue time remains the original plan opening; its expiry cannot exceed
the original post-plan caller expiry. Nothing is backdated or renewed.

| Obligation | Time and authority source |
| --- | --- |
| Current processing | Supplied real epoch/monotonic bracket, cumulative work and inherited deadline; sticky guards through return. |
| Original validity | Authenticated plan, head, caller/grant intervals; original policy, database cutoff and row/delivery bounds. |
| Present execution permission | Not provided by historical replay. |
| Completion or token delivery | Not provided by these primitives. |

Current processing may outlive the original execution deadline, but cannot
exceed its own independently supplied age/skew/deadline. No live verifier is
called with an old timestamp, and no expired observation becomes current.
Current source/configuration/key-cohort checks remain strict; this does not
resolve unknown historical cohorts or close the separate H05 requirement.

## Remaining completion work

The `.155` [dedicated completion composition](oidc-session-activation-completion-recovery.md)
now connects a separate historical bootstrap/owner, original reservation/pending
admission, actual immutable commit/custody readers, enrolled completion signing,
first-exact retention, delivery and no-repeat reconciliation in private source.
The live receiving bootstrap still permits only grant, reserve and SQL-issuer
purposes; none is silently upgraded to historical custody. Dedicated cold
completion key/FD delivery, reader/TLS/journal admission, service launch,
state-peer profile and response integration remain open. These primitives are
not a public route or an installed completion service, and the generic
activation completion rejection remains unchanged.

Protected token release, public target-bound permission/recovery and portal
confirmation remain separate. Step19 is **in progress**, not landed; the active
source total remains **18/26** and production acceptance remains **0/6**.
No builds, tests, parsers, provisioning or runtime verification were performed.

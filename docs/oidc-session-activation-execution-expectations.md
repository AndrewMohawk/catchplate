# Activation execution expectation data

[`authority_oidc_session_activation_execution_expectations._capture_on_work`](../catchplate/authority_oidc_session_activation_execution_expectations.py)
owns an ordinary data graph containing exactly `request`, `scope` and
`journalDigest`. There is no additional schema field: the request operation is
fixed to `oidc.session.activate`.

The helper rejects unknown fields before copying, uses the actual assertion
capture under the supplied shared work, and preserves its 2 MiB, 100,000-node
and depth-12 limits. It requires the actual seven-field typed request and
fifteen-field plan scope, checks the journal digest, and recomputes the genuine
typed-request digest and operation-ID commitment. The returned graph is detached
JSON data, not a verification result or permission token.

No private keys, custody owners, successful result objects or processing clock
window are serialized. Existing scope policies and `deadlineEpochNs` remain
ordinary expected data; this helper neither authenticates their provenance nor
interprets them as live authority. It does not duplicate assertion or policy
semantics or fabricate a window to call a live verifier.

Independent configuration admission and the actual
[receiving replay](oidc-session-activation-execution-replay.md) must still
authenticate original signatures, assertions, policy/subject/root bindings and
all original lifetimes under the caller's existing window. This source slice
does not enable a generic replay family, grant, reservation, SQL execution,
historical recovery or token delivery.

Source-only; no builds, imports or tests were run. Deferred frozen verification
covers closed-field rejection, exact JSON capture limits, changed request and
operation commitments, invalid journal digests and detached-output behavior.

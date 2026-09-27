# Protected activation delivery consumption effects

This source-only pure worker derives a one-use delivery consumption. It neither
decrypts nor returns a token, calls legacy recovery/decryption, executes SQL,
establishes fresh public consent or proves a committed release. The operation
is `oidc.session.activation-delivery.consume`; no generic kernel factory is
enabled by this module. Source remains unbuilt and unexecuted.

## Original inputs and actual current proofs

[`authority_transition_oidc_session_activation_delivery`](../serverware/authority_transition_oidc_session_activation_delivery.py)
provides `_full_transition_with_liveness_on_work(context, *, ...)`, requiring
original `old_token_bytes`, six independent delivery/subject identifiers,
independently admitted current authentication/trust policies, original primary
and complete-range proofs and roots, plus the caller's actual current
work/window/deadline. No incoming successful transition or proof carrier is
accepted. `_full_transition_on_work` accepts the same explicit inputs and
returns the actual `KernelTransition` only.

The closed ten arguments are delivery/session/user/credential IDs, credential
record and challenge IDs, old/new token and assertion digests, and the canonical
business intent. That intent is ordinary data, not permission. The original
64-byte old token is independently hashed and matched to both the typed
arguments and selected delivery; a claimed digest alone is insufficient.

The genuine read helper verifies ten primary rows and seven complete ranges.
Six complete equality populations must be the exact selected session/delivery;
the pending-trust publication range must be empty. Partial observed rows do not
supply uniqueness or absence. The worker then uses only the owned proof-joined
context, including the deterministic audit absence and actual capacity row.

## Current state and original delivery binding

The delivery must be unconsumed and live. Its session must be active, unrevoked,
unexpired and bound to the exact current credential/new-token digest, with no
pending expiry. The credential must remain unrevoked, non-development and
currently eligible under the independently supplied trust/class/hardware policy.
Actual selected RBAC authority/binding and session roles must agree; genuine
trust high-water/publication must match the current policy.

Original session activation trust metadata cannot name a future publication.
An equal current sequence must match its digest/class; a later valid publication
does not automatically invalidate older activation metadata. Current credential
trust remains mandatory, while genuine original activation/completion provenance
is a separate protected-caller obligation.

The used session-binding challenge must name the same subject/session and its
actual canonical payload hash. Its use equals original activation/delivery
creation, within the original pending/challenge interval. An expired used
challenge is never repurposed as fresh assertion permission. Current delivery,
session and provider expiry, row chronology and the maximum original delivery
lifetime are checked against the actual database cutoff and processing clock.

Only the exact `oidc-activation-v1:` ciphertext framing is inspected and hashed.
No AES key is accepted and no AEAD/plaintext claim is made here. Actual delivery
envelope authentication belongs to the separate protected release owner.

## Three deterministic effects, not a release receipt

The worker derives exactly:

1. A full-row delivery CAS changing only `consumed_at` to the admitted database time.
2. A deterministic token-free audit outbox insert.
3. The real shared audit-capacity CAS; a missing/full/invalid counter fails closed.

Already-consumed, stale, revoked, inconsistent or colliding state raises an
error; no no-op denial is returned as success. The result is the closed
`serverware.oidcSessionActivationDeliveryConsumptionEffects/v1` document with
derived-consumption status, subject/delivery identifiers, assertion/new-token/
ciphertext digests, consumption time and `tokenReleased: false`. It contains no
token or ciphertext. The actual row mutation preserves ciphertext unchanged.

`_FullTransition` returns `transition`, `live` and `valid_until_epoch_ns` for this
same invocation only. The real current guard retains original opening samples,
sticky clocks, cumulative work and inherited deadline; the row/window expiry
ceiling is also conservatively clipped to that inherited cap using the unchanged
opening bracket and remains live through final result creation. Work units already include
query, business and capacity work: a future planner must not finalize or count
them twice.

No new outcome table is introduced. Future protected execution must retain and
authenticate its real immutable execution packet and commit marker, including
the exact effects/result and unchanged encrypted delivery row. `consumed_at`
alone is not proof that a token was released and cannot authorize recovery or
another consume. Actual original completion admission, protected execution,
one-use release custody and fresh public/portal permission remain distinct
composition obligations. No tests, imports, parsers, formatters, builds, runtime
or provisioning commands were run for this source change.

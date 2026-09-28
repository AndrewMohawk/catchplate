# Public consume completion receipt

`control_plane_oidc_session_activation_completion_recovery_consume_response.py`
stages fixed historical completion data on the actual fresh consume owner.
It accepts no posted completion, token, successful result carrier or restored
activation permission. The private constructor cannot be called directly.

The HTTP caller stages `_StagedConsumeResponse` inside the real consume context
and calls `finish()` only after that context exits normally. The root-owned
one-use response latch binds the exact terminal, actor and genuine
`_ConsumeCompletion`. While the owner remains live, its final guard delegates
to this terminal, which checks the actual completion receiver and remembers
only narrower windows and nondecreasing clock floors. That genuine receiver
is checked through trust cleanup, separately from its ancestor guards.

After successful actor/startup-lock and owner cleanup, both source-owned
normal-exit markers must be true, the exact terminal association must remain,
and transient owner/actor fields must be cleared. `finish()` checks these facts
and the final original expiry under the same ledger. It does **not** call a
closed actor, owner, planner, authorization, dispatch or completion guard.
This transition reports an already authenticated historical observation; it
does not preserve a permission past cleanup. Finishing is one-use, and any
exception or deadline failure becomes the HTTP caller's fixed unknown result.

Only genuine signed completion and state acknowledgment can yield HTTP 200
with `status: consume-completion-acknowledged`. The body always says
`sessionState: unknown`, `tokenReleased: false` and
`automaticRetryAllowed: false`. It contains no target identity, control
originals, private hints or token. An unacknowledged completion yields the
fixed HTTP 503 `consume-outcome-unknown` body even after normal cleanup.

Before entering the potentially effectful consume context, HTTP may return
`consume-rejected-before-dispatch`; `dispatchState: not-started` describes
only this request. From context entry onward, failures are unknown: missing
records and unsigned observations prove neither SQL nonexecution nor safe
retry. Existing-cookie state is untouched by every response. No signed cookie
send mechanism, token release, current-auth success or browser-delivery
guarantee is introduced by this data-only receipt.

The fixed response uses no-store, no-cache and nosniff headers. A 16 KiB
representation reserve is included before the first historical body, inside
the original 64 MiB allowance; existing immutable originals are referenced,
not copied into public data. The body is capped at 1 KiB and cumulative work
and original clock floors are retained. This is source-defined accounting,
not a Python heap or runtime guarantee.

Source only: no build, runtime, browser, provisioning or production acceptance
has been established. The appropriate fresh release/current-auth session
boundary remains separate from this consume completion receipt.

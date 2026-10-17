# Configured private activation dispatch

[`control_plane_oidc_session_activation_dispatch.py`](../catchplate/control_plane_oidc_session_activation_dispatch.py)
connects actual present permission, post-permission planning and caller signing
to the isolated activation authorizer, reserver and SQL roles. Its existing
`dispatch(...)` method remains SQL-only; the separate
[completion continuation](control-plane-oidc-session-activation-completion.md)
opts into a fixed completion exchange through `dispatch_completion(...)`.
This is source implementation, unbuilt, unexecuted and unprovisioned. Neither
method adds a public route, consume/release handoff, active-session cookie or
public recovery permission. Step 22 remains in progress; production acceptance is 0/6.

## One actual parent continuation

The cold parent exposes only this fixed private composition:

```text
_dispatch_oidc_session_activation(
    *, request, permission_bytes, assertion_bytes, expected_challenge_id,
    live_window, transport_deadline_ns, work
) -> exact unsigned SQL response raw4
```

It bounds the original planning inputs, enters the genuine
[live permission context](control-plane-oidc-session-activation-execution.md)
and calls its single-use `dispatch(...)` method. There is no supplied plan,
verified-grant object, user identity, phase flag, callback, replacement work or
renewed window. The method calls the real
[post-permission planner preparation](control-plane-oidc-session-activation-planning.md),
including the irreversible target-keyed pre-planner claim, before downstream
dispatch. Assertion/approval consumption and durable publications are not
rolled back on later failure.

The explicit execution configuration `/v2` adds fixed reserver and SQL
endpoints plus independently root-admitted `statePredecessor` sequence,
head digest and next fence. `/v1` stays strict and cannot implicitly enable
this continuation. Existing parent v6/v7 and sealed caller key FD205 remain;
there is no new control-plane secret, AES key, history owner or descriptor.

## Exact originals, then genuine public control checks

The control-plane journal retains this closed, ordered prefix beneath the
original finalization claim:

| Stage | Exact original inventory | Required before the next exchange |
| --- | --- | --- |
| Prepared | Authorization, plan, encrypted bundle, canonical expectations, before-vector | Actual caller/plan signature and target admission |
| Grant | Signed grant | Root-enrolled grant signature, exact original commitments and live interval |
| Reserved | Signed reserve, canonical snapshot, signed state ACK | Live computation signature, grant/snapshot/vector joins and independent predecessor/fence ancestry |
| SQL claimed | Empty marker | First irreversible attempt publication and final pending-target check |
| SQL outcome | Exact raw4 observation | Bounded shape; retained before interpreting its diagnostic fields |

The new [fixed records](control-plane-oidc-session-activation-records.md) are
originals/data, not reusable proof. Append and normal-close readback precede
the next socket. Recovered records are read-only; they do not authorize
another exchange. The same live owner cannot repeat its SQL claim. No pending
cookie, permission/session-binding assertion or released-token field is added
to these records; private execution data remains encrypted.

The coordinator freshly admits the signed caller original and its enrollments
using the real owner-continuity clock seam. Grant admission authenticates the
actual root-enrolled authorizer, joins the exact authorization, request,
operation, plan, raw2 frame hashes/counts and original before-vector, and
rejects renewed original intervals. After/result claims are signed grant
assertions here, not a claim that the public caller replayed private history.

Reservation admission authenticates the live enrolled computation signature,
the canonical snapshot committed by that request, and the enrolled state ACK.
It joins the snapshot to the authenticated grant, the exact held before-vector
and signed after-vector identity. The existing records verifier checks the
independent predecessor, fence, request identity, vectors and original
interval. It derives the exact successor observation as sequence
`predecessor + 1` and the domain identity of the signed ACK original. No future
head is guessed and no returned head scalar becomes current-state authority.

These public checks do not replace genuine private semantic replay. The actual
authorizer, reserver and SQL receiving roles still perform their own original
admission and full replay using their isolated custody. In particular, the SQL
service retains its independently root-pinned current pending scope; the
caller's authenticated successor observation does not replace it.

## Original allowance and the irreversible phase

Each [guarded transport](oidc-session-activation-caller-transports.md) receives
the same cumulative work, absolute deadline and actual current guard. All
originals and maximum subsequent responses/headers fit the existing aggregate
bound before network allocation. Calls are direct charging helpers, not
wrapped inside a metrics-constant callback. There is one exchange per fixed
role, no fallback endpoint, retry or automatic recovery.

Pending-session and exact post-permission credential checks remain mandatory
through planning, signing, grant/reserve admission, original retention and
the durable SQL claim. Immediately after the last such check, the fixed
coordinator seals the exact admitted raw8 and enters the terminal SQL phase
before opening its socket. No response or externally supplied success object
can perform that transition.

SQL activation intentionally changes the pending session/token/credential
rows. Only their obsolete unchanged-row check stops after this phase change.
The exact active parent, PID/thread, key and FD identities, runtime receipt,
original authorization/grant/reserve bounds, shared work and sticky clock
floors remain enforced. The actual final clock check retains the narrowed
skew and epoch/monotonic ceilings through I/O, outcome retention and context
exit. The phase cannot sign again, reenter permission, replace originals or
renew an allowance.

## An SQL observation is not activation success

The returned raw4 is the unsigned `observed-commit` or `uncertain` branch,
optional pending/packet locators and bounded marker. After retaining that
original, a supplied pending locator must match the authenticated original
ACK identity. This consistency check still does not authenticate the marker,
prove commit/completion/current state or authorize token delivery.

Failure after possible SQL send is terminal even when no response is retained.
The SQL claim survives; absence of a marker never proves nonexecution. The
separate completion variant proceeds only from an actually received, retained
SQL response; it does not retry a failed exchange or change this method's
return contract. Consume/release, public dispatch response and independently
authorized recovery remain necessary before any user-facing activation or
cookie-delivery claim.

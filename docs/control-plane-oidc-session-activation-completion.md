# Configured private activation completion continuation

[`control_plane_oidc_session_activation_completion.py`](../catchplate/control_plane_oidc_session_activation_completion.py)
extends the fixed private activation dispatch with one genuine completion
service exchange and public verification of its signed originals. This is
source only: unbuilt, unexecuted and unprovisioned. It adds no public route,
token release, active-session cookie, SQL retry or public recovery authority.
Step 22 remains partial; production acceptance remains 0/6 verified.

## Explicit cold selection, unchanged SQL-only API

The actual parent facade is:

```text
_dispatch_oidc_session_activation_completion(
    *, request, permission_bytes, assertion_bytes, expected_challenge_id,
    live_window, transport_deadline_ns, work
) -> (sql_response_raw4, completion_response_raw4)
```

Inside the genuine permission context it calls the fixed, single-use
`dispatch_completion(...)` method. Existing `dispatch(...)` remains SQL-only
with its original raw4 return. The completion branch is selected before any
planning or attempt claim; explicit nested execution configuration `/v3`
supplies its root-admitted fixed completion endpoint. Older `/v1` and `/v2`
configurations do not implicitly enable it. No extra key, descriptor or
private history custody enters the UID/GID 65532 control plane.

The new completion dispatch transport carries only the literal
`complete-oidc-session-activation` and the exact signed caller authorization
original. Its separately selected server launch profile compares that original
byte-for-byte to the service's independently root-admitted authorization, then
uses only its own packet pin. The old packet-selector profile remains strict.
The caller neither predicts a future packet digest nor promotes an unsigned
SQL locator to authority. Raw4 does not carry packet identity, so this
continuation makes no returned packet-identity claim.

## One irreversible continuation on original authority

The existing [private dispatch](control-plane-oidc-session-activation-dispatch.md)
performs permission, post-counter-update planning/signing, original grant and
reservation admission, and durable SQL claim before sealing the exact raw8.
The completion variant uses a separate source-fixed phase, not a posted phase
flag or a successful response object. Pending-row equality remains mandatory
until SQL can intentionally change those rows. The actual parent, keys,
descriptors, receipt, original authorization/grant/reserve and cumulative
work/window remain guarded afterward.

An actually received and retained unsigned SQL `uncertain` response may lead
to the one completion exchange; only the actual completion service determines
whether its independently scoped original commit exists. This is not SQL
re-execution. A failed or missing SQL response remains terminal, with no hidden
reconnect or completion fallback. No recovered journal record resumes this
live continuation and no automatic retry is authorized.

Before the first exchange, the complete held-original inventory and maximum
completion response/header allowance fit the existing 64 MiB aggregate bound.
Each transport carries the original cumulative work, deadline and actual
current guard. The new completion interval can only narrow those bounds;
expiry never opens another window or revives expired execution permission.

## Original retention before interpretation

The final `completion-outcome` stage retains the unchanged raw4 under the same
live finalization claim, after the SQL outcome:

| Branch | Exact original frames |
| --- | --- |
| Acknowledged | `acknowledged`, complete-request digest, signed complete control, signed state ACK |
| Uncertain | `uncertain`, three empty frames |

The [fixed journal](control-plane-oidc-session-activation-records.md) publishes
and normally closes/readbacks these originals before branch, identity or
signature interpretation. Its bounded I/O allowance is charged before the
stable native callback. Retention is not semantic admission; even a later
rejected response remains evidence rather than permission to resend.

## Public signed-control verification, not private replay custody

The existing full completion response verifier requires the exact historical
custody owner at UID/GID 65503 and genuine private AES/history replay. It is
not called under UID 65532 and its accepted owner purpose is not widened.
The actual isolated completion service retains that full replay and genuine
read-only commit observation before signing and durable state delivery.

This public continuation independently re-admits the held grant, reserve,
snapshot and state ACK originals. It joins the exact authorization identity,
grant capability, independent predecessor/fence, before-vector and signed
after-vector. The neutral marker encoder only projects those same-call
authenticated controls; it supplies no replay authority.

For an acknowledged response, genuine root-enrolled completion and state
signature checks bind the complete-request identity, exact next sequence and
previous signed ACK identity. Every complete-control marker field must match
the held originals. The signed inner observation must be canonical, contain
the exact full marker and after-vector digest, and place its observation time
inside the signed completion interval. Actual current-time admission and
only-narrowing clock/skew limits remain enforced through context exit.

These checks authenticate the enrolled roles' exact statements. They do not
make the public caller a private-history verifier, prove independently current
database/session state or authorize token release. Both returned tuples contain
only ordinary original bytes; no later admission API accepts this call's
success or a reconstructed marker as proof. The completion/consume/release
handoff and public activation response still need their own genuine joins.

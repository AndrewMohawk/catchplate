# Original post-permission activation planning

[`control_plane_oidc_session_activation_planning.py`](../catchplate/control_plane_oidc_session_activation_planning.py)
connects the actual live permission context to the isolated planner and then
to the existing dedicated caller signer. This is a private, source-only partial
step 22: no public activation POST, grant, reservation, protected SQL dispatch,
completion, cookie change or token release is supplied. It is unbuilt,
unexecuted and unprovisioned.

## Actual parent entry

The cold parent exposes:

```text
_prepare_oidc_session_activation_authorization(
    *, request, permission_bytes, assertion_bytes, expected_challenge_id,
    live_window, transport_deadline_ns, work
)
    -> (originals_raw2, expectations, before_vector_bytes, authorization_bytes)
```

`_planning_inputs(assertion_bytes, expected_challenge_id)` checks immutable
types and source bounds without callbacks before entering the real permission
context. The original HTTP `Request` and permission body still go through
[present target permission](control-plane-oidc-session-activation-permission.md),
not an accepted permission result. While that exact parent/PID/thread context
holds the original owner and trust locks, its fixed
`prepare_authorization(*, assertion_bytes, expected_challenge_id)` method
performs one preparation and calls the actual `authorize` method once.

There are two different WebAuthn actions. The permission assertion binds the
retained finalization target and consumes its mutation challenge, including a
credential-counter CAS. The separate activation assertion answers the existing
`/api/auth/session/webauthn/options` session-binding challenge. Generate the
permission assertion before the session-binding assertion so their actual
authenticator counters can increase in that order. The registration challenge
cannot substitute for the unused session-binding challenge. The isolated
planner genuinely verifies that second assertion against its original rows;
this client does not accept a browser's claimed verification result.

## Root originals before one private exchange

The explicit [v7 planning configuration](control-plane-oidc-session-activation-planning-bootstrap.md)
holds only the original root-signed planner bootstrap and a fixed endpoint.
No new secret or descriptor is delivered to the control plane. The client
owns the actual pending-cookie original, assertion, independent challenge and
all parent configuration/target graphs before native or cryptographic callbacks.
It freshly verifies the planner bootstrap on the same cumulative work and
original clock bracket, joining configuration, generation, runtime cohort,
planner public key, original state enrollment and endpoint timeout to the
actual cold parent. The before-vector comes from that genuine root original.

Before any planner socket, the client publishes the dedicated
[token-free dispatch claim](control-plane-oidc-session-activation-dispatch-attempt.md).
Its slot is the genuine retained finalization `localDigest`, with the actual
permission-binding digest, enrolled caller identity and source cohort as
metadata. Publication and normal-close readback must succeed before dispatch.
The same slot cannot be reused after restart, a source change, a new permission
challenge or a different plan. It stores neither assertion nor old/new token,
request/response originals, plan authority or an alleged outcome.

The new bounded planner profile sends the fixed raw8 plus one tightening-only
epoch deadline. A source-fixed real owner guard and the same work meter remain
active through every native I/O chunk and normal close. A separately tightened
response ceiling reserves the already-held originals, before-vector, headers
and maximum authorization output before response-body allocations. There is
one socket exchange, no fallback to the legacy profile and no automatic retry.
Planner uncertainty, malformed data, expiry and uncertain cleanup are terminal;
the durable claim and any planner-side retained originals remain intact.

## Independent response joins and signed-original output

Framing and root-listener peer identity do not authenticate the response. The
client requires exact canonical request/scope originals and independently
derives scope from root-admitted planner policy and the current retained target.
Only a smaller returned deadline may narrow that scope. The typed request must
match the exact user, pending session, credential/record, independent challenge,
actual old-cookie digest, original assertion digest and root delivery TTL.
The actual planner signature, original plan locator and post-permission issue
time are checked before the existing caller producer signs the exact raw2,
journal commitment, request and original complete vector.

The journal locator and encrypted bundle remain originals/data: the control
plane neither decrypts them nor claims full history replay or remote durability.
Later grant and execution consumers still owe their genuine original replay
and independent current-state admission. The returned tuple has no success
flag or reusable authority carrier; every later consumer must authenticate its
original inputs again.

Planner launch, session, returned scope and plan expiry only narrow the same
context's original window/deadline. Actual narrowed clock checks enforce age,
skew and dual-clock bounds through I/O, signing and context exit; newer clock
floors persist into the next owner check. Pending-session/post-permission
credential checks are never disabled in this preparation-only slice. Public
dispatch, the later irreversible SQL state transition and independently
authorized public recovery remain separate implementation work. Production
acceptance remains 0/6.

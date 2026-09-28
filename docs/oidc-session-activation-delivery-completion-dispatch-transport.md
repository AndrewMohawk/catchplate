# Consume completion dispatch transport

The explicit dispatch profile connects the same live control-plane consume
attempt to the separately admitted completion service. It sends the exact signed
consume caller authorization, not the unsigned SQL response's packet locator.
Framing and socket identity are not completion, current session or release proof.
This source is unbuilt, unexecuted and unprovisioned.

## Closed request profile

[`authority_oidc_session_activation_delivery_completion_dispatch_transport.py`](../serverware/authority_oidc_session_activation_delivery_completion_dispatch_transport.py)
defines exactly two request frames: literal
`complete-oidc-session-activation-delivery`, then the original signed consume
caller authorization. Request magic is `SWODCM02`. Each frame and the whole
exchange are bounded before body allocation; trailing bytes fail closed.

Only signed service launch
`serverware.oidcSessionActivationDeliveryCompletionLaunch/v2` selects this
grammar and peer UID/GID 65532. The service keeps its existing isolated UID/GID
65497 and inherited resources. Its actual owner must compare the received
authorization byte-for-byte with the genuinely admitted root-held original,
then use only its independently pinned packet and private historical custody.
Neither this decoder nor a matching digest substitutes for that owner check.

The `/v1` service launch remains selector-only at request peer 65497 with
`SWODCM01`. It does not accept dispatch bytes or the new caller peer. Socket ACL
selection must match the independently admitted launch profile; exposing one
socket to both peers is not the implementation. The actual caller connects to
the same fixed completion path and checks the root-created listener's kernel
peer 0:0, independently of the worker's service UID.

## Original allowance and unchanged response

The private `_socket_request_on_work(endpoint, *, originals, deadline_ns, work,
current)` adapter uses the ninth literal profile of the
[guarded caller engine](oidc-session-activation-caller-transports.md). It keeps
the original cumulative work and current guard through connect, peer checks,
bounded sends/receives, exact EOF and normal close. The configured timeout may
only shorten the inherited deadline. Allocation is precharged, and any failure
is terminal with no reconnect or retry.

The response remains `SWODCR01` and the existing raw4 grammar:

- `acknowledged`, completion-request digest, signed complete control, state ACK;
- or `uncertain` followed by three empty frames.

The returned identity is not a packet echo. The caller must durably retain those
originals before interpreting status, identity or signatures, then authenticate
signed controls against its own actual consume grant/reserve/snapshot/ACK
originals. Public control checks do not transfer private AES/history custody,
prove current session state, or authorize token release. The full private
completion verifier still requires its genuinely admitted historical owner.

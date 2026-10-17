# Activation SQL raw8/raw4 transport

[authority_oidc_session_activation_sql_transport.py](../catchplate/authority_oidc_session_activation_sql_transport.py)
defines a separate fixed wire purpose for the
[genuine activation SQL bridge](oidc-session-activation-sql.md), not semantic
admission or permission from framing.

| Fixed profile | Value |
| --- | --- |
| Request / response magic | `SWOASQ01` / `SWOASR01` |
| Unix stream path | `/run/catchplate/oidc-session-activation-execution/sql.sock` |
| Service UID/GID | `65504:65504` |
| Accepted request peer | `65532:65532`, admitted by the service before body read |
| Client's listener peer | `0:0`, for the root-created inherited listener |
| Timeout | Exact integer, 1–30 seconds; only narrows the inherited deadline |

Request raw8 has this fixed order:

1. Original signed activation caller authorization.
2. Original signed activation plan.
3. Original encrypted execution bundle.
4. Canonical closed `{request, scope, journalDigest}` expectation data.
5. Original execution grant.
6. Original signed reserve request.
7. Original computation snapshot.
8. Original state acknowledgment.

The before-vector is independently held by the service, never a ninth frame.
Raw5 and reservation raw3 use their existing fixed source ceilings. This layer
checks immutable byte/frame shape, including the bounded encrypted frame, but
does not decode the expectation JSON, decrypt, verify signatures or issue SQL.

Response raw4 uses the existing bounded unsigned outcome encoding:
`(status, pendingDecisionDigest, packetDigest, marker)`.
`observed-commit` requires both actual issuer IDs and a 2–4096 byte marker;
`uncertain` permits both actual IDs or two empty frames, and requires an empty
marker. No caller-selected or guessed IDs are authorized by this codec.
The distinct activation path/magics separate the exchange; the actual bridge
joins the marker's fixed activation operation and complete expected contents.

All individual lengths and the whole 64 MiB exchange ceiling are checked before
body allocation. That ceiling includes the 72-byte request header, 40-byte
response header and the maximum 4,253 response-body bytes, reserved in advance.
The bundle's individual cap cannot enlarge it. Existing raw5 group limits are
also preserved. Empty frames are permitted only by the fixed response shape.

`_socket_request(endpoint, *, originals, deadline_ns)` requires a positive
inherited absolute monotonic deadline. It admits the fixed listener peer before
sending, half-closes after one request, reads the exact response plus EOF and
closes on all exits. `_recv_request` and `_send_response` use the service's
original pre-peer/body bound. No retry, alternate endpoint, budget or renewed
window is provided. The serving lifecycle owns its terminal accepted-connection
latch; malformed or disconnected input can simply close without an outcome.

A marker/peer/shape match is not signed completion, currentness, browser token
delivery or successful public activation. Timeout and missing response are not
proof of rollback or permission to retry. Socket ACL provisioning and runtime
behavior remain independently unverified: no tests, rendering, runtime or
deployment were performed for this source-only change.

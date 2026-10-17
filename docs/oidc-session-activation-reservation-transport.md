# Activation reservation original transport

[The fixed transport](../catchplate/authority_oidc_session_activation_reservation_transport.py)
carries five immutable request originals and three response originals. It uses
the existing deadline/Unix-peer I/O primitives; framing is not semantic admission,
present-purpose permission, private custody or action-time currentness. This is
source-only implementation, not build, runtime or provisioning evidence.

## Exact inventories and bounds

The request order is original caller authorization, signed activation plan,
encrypted execution bundle, canonical closed expectation JSON
`{request, scope, journalDigest}`, and original signed execution grant. The
transport bounds that inventory without parsing its JSON, verifying signatures
or opening the encrypted bundle. Only the bundle's fixed outer frame is checked.
The actual caller/service must authenticate those exact originals under
independently admitted scope and private custody.

The response order is original signed reserve request, canonical computation
snapshot and signed state acknowledgment. Their source-derived ceilings are
256 KiB, 16 KiB and 16 KiB. Request ceilings come from the actual authorization,
plan, bundle, expectations and grant modules; they do not override the aggregate.
Only the private execution-original bundle is ciphertext, not the entire request.

The 64 MiB whole-exchange limit reserves the maximum 288 KiB response and both
headers before any request body allocation. Request/response headers are 48/32
bytes: fixed eight-byte magic plus one unsigned big-endian eight-byte length
per original. Every individual and aggregate length is checked before body
reads. Exact immutable tuple/byte types, bundle minimum size, half-close and
EOF reject changed counts, trailing data and truncated inventories.

## Fixed endpoint and lifetime

Request/response magic is `SWOARQ01` / `SWOARR01`. The only endpoint is
`/run/catchplate/oidc-session-activation-execution/reserver.sock`.
Its configuration is the exact tuple `(path, integer_timeout_1_to_30, 0, 0)`:
the client expects the kernel peer identity of the original root-created
inherited listener, not the worker's later UID/GID `65505`. The serving owner
must admit request UID/GID `65532` before calling the frame/body reader.
Socket ownership, DAC and service deployment remain independent provisioning.

`_socket_request(endpoint, *, originals, deadline_ns)` requires a positive
original absolute monotonic deadline and returns unchanged, unverified raw3.
Its sole exchange bound is the minimum of that inherited deadline and the
configured transport timeout. The same bound covers connect, actual peer check,
request send, write half-close, response body/EOF and return. It does not open
a verification window or allocate new validation work.

The service seams are `_recv_request(connection, *, deadline_ns)` and
`_send_response(connection, originals, *, deadline_ns)`.
`_originals(values, *, response)` is the shared bounded shape check, not an
authenticated result carrier. The serving owner must retain a genuine
acknowledgment through the [durable delivery profile](oidc-session-activation-reservation-delivery.md)
before sending raw3, then close the connection to finish response EOF.

Every call makes one connection attempt. Errors close the connection and
propagate; there is no retry, alternate endpoint, regenerated request, SQL or
completion. Missing or late response is uncertainty, not proof that reservation
did not occur. Native I/O still needs an external watchdog.

## Deferred verification

After source freeze, verify per-frame/aggregate/header boundaries, exact request
and response order, malformed bundle framing, peer-before-body admission,
partial I/O, EOF/half-close, deadline expiry/closure and the absence of retries.
No such execution was performed for this source-only batch.

# Private consume SQL transport

`authority_oidc_session_activation_delivery_sql_transport.py` defines one fixed
raw8/raw4 exchange for the [cold consume SQL service](oidc-session-activation-delivery-execution-sql-service.md).
It transports immutable originals, not a successful admission object, keys or
plaintext token originals. Source only: no socket, service or workload is
provisioned or verified by this module.

The request magic is `SWODSQ01`; response magic is `SWODSR01`. The sole endpoint
is `/run/serverware/oidc-session-activation-delivery-execution/sql.sock`. The
service runs as UID/GID 65498 and admits peer 65532 before bodies. The client
expects the root-created listener's kernel UID/GID 0:0, not the dropped service
identity. Timeout is an integer from 1 to 30 seconds, always intersected with the
mandatory positive inherited absolute deadline.

Request order is caller authorization, signed consume plan, encrypted consume
originals, canonical closed expectations, consume grant, signed reserve,
computation snapshot and state ACK. Bounds come from the actual consume
reservation request and record codecs. The before vector and independent
pending/predecessor pins belong to the root-admitted service; they are not
additional caller-selected frames.

Response order is status, pending-decision digest, packet digest and marker.
`observed-commit` requires two canonical digest strings and a 2–4096-byte marker.
`uncertain` allows either both digest strings or both empty and always an empty
marker. The actual service emits uncertainty only with a genuine still-live
same-call continuation, and emits IDs only if actually known. Framing alone does
not validate the marker or authenticate any execution outcome.

Each frame has an eight-byte big-endian length. The 72-byte request header and
40-byte response header both count toward the 64 MiB whole exchange. Before body
allocation the request budget reserves both headers and the full 4,253-byte
maximum response, in addition to actual per-frame and consume raw5 subgroup
limits. The encrypted frame also passes its distinct consume framing check;
transport never decrypts or treats ciphertext shape as proof. Trailing bytes,
truncated frames, alternate magics and endpoints fail closed.

`_recv_request`, `_send_response` and `_socket_request` retain their mandatory
`deadline_ns`; `_originals(values, response=...)` captures only the exact fixed
byte tuples. The client half-closes its request, requires response EOF and never
retries. Returned raw4 is unverified unsigned evidence, not completion, current
pending authority, absence of commit, token release or permission to repeat SQL.
An absent/uncertain response cannot undo a durable packet or attempt.

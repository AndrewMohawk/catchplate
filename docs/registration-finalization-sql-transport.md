# Finalization SQL original transport

The source [transport](../serverware/authority_registration_finalization_sql_transport.py)
defines one dedicated raw13/raw4 exchange for the [cold finalization SQL
worker](registration-finalization-sql-service.md). It is unbuilt and unexecuted.
Framing alone neither installs that worker nor grants SQL permission. The
separate [public execute action](public-registration-finalization-sql.md) now
uses the genuine retained caller and its fresh-purpose admission.

The fixed endpoint is `/run/serverware/registration-finalization/sql.sock`, with
root socket-activation listener UID/GID `0:0`, a bounded 1–30 second duration,
request magic `SWRFSQL1` and response magic `SWRFSLR1`. These are distinct from
the evidence SQL path. Listener peer checks identify the local socket owner,
not measured execution, original signatures or independent currentness.

The request is finalization grant raw10 (dedicated caller authorization,
custody raw7, complete before-vector and execution grant), followed by reserve
request/snapshot/acknowledgment raw3. Actual finalization field and group bounds
are reused; the combined body cannot exceed 64 MiB. The entire length vector is
checked before any body allocation. Enrollment originals remain independently
admitted inputs of the owning service, never caller-selected request fields.

The response reuses only the older evidence SQL transport's bounded local
outcome carrier, not its request profile, endpoint or authorization:

| State | Pending decision ID | Packet ID | Marker |
| --- | --- | --- | --- |
| `observed-commit` | Canonical SHA-256 locator | Canonical SHA-256 locator | 2–4096 unsigned bytes |
| `uncertain` | Both locators present, or both empty | Same availability as pending ID | Empty |

An empty pair does not prove absence. Present IDs must originate in actual
protected issuance, and an unsigned marker is not signed completion. The
[actual composition](registration-finalization-sql.md), not this codec, owns
those obligations. No response is a completed-registration or session-activation
receipt, and no error permits an automatic retry.

`_socket_request(endpoint, *, originals, deadline_ns)` requires the original
positive absolute deadline. The endpoint duration can only shorten it. One
connection covers peer admission before send, exact frame, half-close, response
and exact EOF. The complete request/response body also stays within 64 MiB.
The codec adds no work allowance, parser, key, fallback endpoint or reconnection.

The [cold caller profile](control-plane-registration-finalization-custody.md)
independently pins the endpoint and pending state. The [private caller](control-plane-finalization-sql.md)
and dedicated cold worker now connect the exchange in source. The caller
requires the finalization grant locator and exact retained raw13, genuinely
admits pending scope, then durably claims local dispatch before sending.
Bounded returned raw4 is durably retained before semantic/lifetime acceptance;
storage is opaque, and uncertainty, mismatch or expiry never clears the claim.
Only an accepted unsigned `observed-commit` reaches the public success projection.

The configuration property itself performs no request. Actual provisioning,
separately signed finalization completion/recovery, OIDC activation and
independent action-time authority remain open. No public response treats a
reserve acknowledgment or this transport's marker as a current-head witness.

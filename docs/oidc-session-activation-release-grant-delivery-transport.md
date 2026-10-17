# Exact release-bootstrap staging transport

This source-only exchange delivers the exact newly issued server-bootstrap
original from the private issuer to root delivery. It does not grant authority,
write files, deliver keys, start the release worker or prove token readiness.
It adds no configurable generic transport profile.

The fixed endpoint is
`/run/catchplate/oidc-session-activation-token-release/bootstrap.sock`.
Root delivery checks issuer request peer `65496:65496` before request bytes;
the issuer checks the root-created listener peer `0:0` before sending bytes.
The independently configured endpoint tuple is `(path, timeout, uid, gid)`;
timeout is bounded to 1–30 seconds and may only shorten the supplied absolute
deadline. Socket peers are not substitutes for genuine root-original admission.

## Closed frames and original identity

Request magic `SWOGDQ01` carries exact raw2:

1. `stage-oidc-session-activation-release-bootstrap`.
2. The immutable server-bootstrap original, 2 bytes through the actual
   `oidc_session_activation_release_bootstrap.MAX_BYTES` (16 MiB).

Response magic `SWOGDR01` carries only `(b"staged", bootstrap_identity_bytes)`.
The identity is exactly 71 ASCII bytes under the existing
`catchplate.oidcSessionActivationReleaseClientServerBootstrapIdentity/v1`
domain. The helper calls the actual client authorization module's
`_server_bootstrap_digest_on_work`, hashing the original itself, not its decoded
payload, an echo or a caller-supplied digest. The issuer independently computes
its outgoing original identity and rejects any different ACK identity.

Both headers are exactly 24 bytes: eight magic bytes and two unsigned eight-byte
big-endian lengths. Response lengths are exactly `(6, 71)`, totaling 77 bytes.
The maximum request, response and both headers fit the existing 64 MiB exchange
ceiling. That wire bound supplies no work or time allowance. There is no error,
uncertainty, retry or alternate response status.

An actual receiver may send `staged` only after it genuinely authenticates the
original and establishes its exact sealed/resource-staged configuration. This
ACK does not assert permanent privilege drop, release-service execution,
readiness to accept a token request, durable token release, present session state
or eventual HTTP delivery. The framing helper cannot itself establish staging.

## Fixed APIs and owned lifetime

```text
_originals(values, *, response)
_bootstrap_identity_on_work(original, *, deadline_ns, work, current) -> ASCII71 bytes
_recv_request(connection, *, deadline_ns, work, current, maximum_bootstrap_bytes=None)
_send_response(connection, originals, *, deadline_ns, work, current)
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current, channel)
```

`maximum_bootstrap_bytes`, when supplied, must be an exact integer from 2 through
16 MiB. It only tightens header admission before any body allocation. The root
receiver computes this from its independently held aggregate original inventory
and remaining reserved work; omitting it keeps the wire cap, not a new aggregate
allowance. Exported request/response headers, limits and `MAX_BOOTSTRAP_BYTES`
allow the receiver to reserve its actual framing and originals explicitly.

Server receive/send retain the receiver's accepted socket ownership and never
close or detach it. The private issuer client requires the actual source-fixed
`oidc_session_activation_release_grant_issuer_startup._DeliveryChannel`, not a
callback, descriptor list or successful result. Its `check` binds the exact
owner, endpoint, original work/deadline and actual current bound method; `open`
owns its nonblocking socket before the first post-allocation guard; `connected`
pins the real root peer; `close` closes and unregisters that one socket.
Transport calls this close once on every terminal path after the class check,
including failure, and never closes or detaches the socket itself.

Actual guarded release chunks precharge bounded allocations and retain current
checks outside stable-ledger native callbacks through connect, peer admission,
every send/receive chunk, half-close, exact EOF and terminal cleanup. Cleanup
uncertainty suppresses the ACK; neither connect nor close is retried. The caller
gets a matched ACK only after established close and a final original guard.

The frame schema adds no private-key, token, cookie or separate issuer-policy
parameter. Resource declarations inside the signed bootstrap still require
genuine receiver admission; bounded byte shape alone cannot authenticate them.
Source is unbuilt and unexecuted; this protocol alone proves no installed
service, real resource provisioning or production acceptance.

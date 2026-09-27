# Private release transport

[`oidc_session_activation_release_transport.py`](../serverware/oidc_session_activation_release_transport.py)
provides one bounded local exchange for the actual
[release startup](oidc-session-activation-release-startup.md) and
[finite service](oidc-session-activation-release-service.md). The root-admitted
bootstrap selects `live-release` or `recovery`; a request cannot select or change
that authority. These are source interfaces, not built, executed, provisioned or
production-verified behavior.

## Closed original framing

Every header contains an eight-byte magic followed by one big-endian unsigned
64-bit length per field. The independently held profile fixes the magic, count
and complete length grammar before any request body allocation.

| Field | Live raw7 | Recovery raw8 | Byte bound |
| --- | --- | --- | --- |
| 1 | `open-oidc-session-activation-release` | `recover-oidc-session-activation-release` | Exact ASCII purpose: 36 / 39 |
| 2 | Original signed release proof | Same | 2–65,536 |
| 3 | Original proof enrollment | Same | 2–16,384 |
| 4 | Original signed release intent | Same | 2–65,536 |
| 5 | Original intent enrollment | Same | 2–16,384 |
| 6 | Old token | Same | Exactly 64 |
| 7 | Original delivery envelope | Same | Exactly 100 |
| 8 | Absent | Exact retained outcome record | 2–65,536 |

The live request magic is `SWORLQ01`; recovery uses `SWORRQ01`. No alternate
operation, optional field, JSON wrapper, success DTO or legacy framing is
accepted. The transport keeps immutable bytes and does not decode or admit
their signed contents. Startup calls the actual original-only release or
recovery method once.

The only response is raw2 under `SWORRS01`: a canonical 71-byte ASCII
`sha256:` request identity and the actual 64-byte token. The identity frames the
entire exact ordered request, including its purpose, under
`serverware.oidcSessionActivationReleaseTransportRequestIdentity/v1`.
The client checks the echo, but echo, framing and local peer credentials are
**not independent response authentication**. Component 16.4 remains separate.

Both headers and the maximum response are reserved in the whole-exchange
calculation before request bodies: live is at most 164,263 bytes and recovery
229,810 bytes, below the fixed 64 MiB aggregate ceiling. The response including
its header is exactly 159 bytes. Complete received lengths are validated before
body allocation, and all body read/copy work is charged before the first body.
Headers, bounded chunks, sends, peer checks and EOF also consume the original
cumulative work. Available work can be less than these wire maxima.

## Actual guard and ownership

The fixed Unix endpoint is
`/run/serverware/oidc-session-activation-token-release/release.sock`.
The service role is UID/GID 65502 and the request peer must be 65532:65532 before
any magic, length or body is read. The private client pins the root-created
listener peer to 0:0. Its exact endpoint tuple is `(path, timeout_seconds, 0, 0)`,
with timeout 1–30 seconds; that cap only shortens the supplied absolute deadline.

The private helpers are:

```text
_recv_request(connection, *, expected_profile, deadline_ns, work, current)
    -> immutable raw7 or raw8
_request_identity_on_work(originals, *, profile, deadline_ns, work, current)
    -> request identity ASCII bytes
_send_response(connection, originals, *, deadline_ns, work, current)
    -> None
_socket_request(endpoint, *, profile, originals, deadline_ns, work, current)
    -> unverified raw2
```

`current` is a mandatory internal guard, not a wire input or reusable success
value. The service supplies a fixed closure that calls its actual startup
owner, retains identical work and the original opening bracket, and rejects
policy or deadline widening. Its return value is ignored. A future receiving
caller must supply its own actual independently admitted guard and account for
its owned client socket; the framing helper does not construct that authority.

The guard runs before and after blocking readiness and immediately before and
after each actual native read or send. Thus an older numeric I/O cap cannot
authorize a chunk after the real owner has narrowed intent/proof or recovery
lifetime. `select.select` uses the existing nonblocking socket without creating
a selector descriptor. Partial I/O continues only inside this one bounded frame;
native errors are terminal. Work is charged before native callbacks, whose
ledger metrics must remain unchanged; the actual authority guard stays outside
those callbacks and may itself charge work, but cannot reset its ledger.

Startup alone owns acceptance and the accepted socket. Transport never closes,
detaches, duplicates or changes that server socket's blocking state. The
[service](oidc-session-activation-release-service.md) closes through startup's
guarded ownership seam, supplying response EOF. Request EOF follows the
client's write shutdown; trailing bytes in either direction are rejected.
Only `_socket_request` owns its newly created client socket. It requires exact
response EOF and a successful normal close with current guards before returning
even unverified response bytes. Cleanup still attempts that owned close after
guard failure, without retrying a possibly closed descriptor.

## Failure and secret boundary

There is no error or `uncertain` response. Failed peer, admission, budget,
currentness, framing or cleanup ends the connection without a successful
response. A partial token send may already have occurred: failure is not proof
of non-delivery, record rollback or permission to retry. There is no automatic
retry, second response, token regeneration or delivery acknowledgment.

The old token and successful response are secret bytes on this private local
exchange; they must not enter logs, exception messages or public response
wrappers. The store's existing exact outcome survives late uncertainty. This
transport supplies no signer, history key, AES key, SQL authority, fresh
allowance, recovery permission or public/portal handoff. Independent receiving
verification and the authorized private caller composition remain later work.

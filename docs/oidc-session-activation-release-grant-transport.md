# Fixed release-grant issuance transport

Source only, unbuilt and unexecuted. This framing module supplies one bounded
exchange at `/run/catchplate/oidc-session-activation-token-release/grants.sock`.
The service checks caller peer `65532:65532`; the caller checks the root-created
listener peer `0:0`. It selects no service UID, starts no worker and provisions
neither a listener nor issuance authority. Peer and shape checks are not grants.

## Exact originals

Request magic is `SWOGIQ01`. The exact raw8 is:

1. `issue-oidc-session-activation-release-grants`.
2. The existing LIVE release purpose, `open-oidc-session-activation-release`.
3. Signed release proof.
4. Original proof enrollment.
5. Signed release intent.
6. Original intent enrollment.
7. The ephemeral 64-byte old token.
8. The exact 100-byte encrypted delivery envelope.

The last seven frames use the actual release transport's LIVE length and
original-inventory checks. Recovery frames are not accepted. No issuer policy,
proof-worker bootstrap, endpoint, filesystem path, resource pin or successful
authority object is request data. The issuer must independently hold and admit
its own root policy, original scope and resources before any issuance.

Response magic is `SWOGIR01`. Exact raw2 contains client authorization bytes
then server bootstrap bytes. Caps come from their actual original contracts:
16 KiB and 16 MiB respectively. Each frame may contain zero through its fixed
cap bytes so a received bounded original can be retained before admission.
There is no status, error or uncertainty frame. Empty, malformed or correctly
shaped frames provide no issuance or release authority; genuine receiving
admission must authenticate both originals after durable retention.

Headers are eight magic bytes followed by one unsigned big-endian eight-byte
length per frame: 72 request bytes and 24 response bytes. The original LIVE
request limits, response caps and both headers must fit the existing 64 MiB
whole-exchange ceiling. The ceiling does not replenish the caller's work.

## Guarded ownership and allowance

The private APIs are:

```text
_originals(values, *, response)
_recv_request(connection, *, deadline_ns, work, current)
_send_response(connection, originals, *, deadline_ns, work, current)
_socket_request_on_work(endpoint, *, originals, deadline_ns, work, current)
```

The endpoint is the exact configured tuple of fixed path, bounded 1–30 second
timeout and root listener UID/GID. The timeout only tightens the inherited
absolute deadline. The generic caller's twelfth literal entry,
`_release_grants_on_work`, retains the same cumulative work, limits and actual
positive epoch-returning current guard through native chunks and terminal
cleanup. It creates no replacement clock window or work allowance.

Server receive/send reuse the actual guarded release chunks. Fixed peer
admission precedes request framing; every body length is checked and the full
body allocation is charged before any body allocation. Real current checks
bracket native I/O outside stable-ledger callbacks. Exact EOF is required on
received frames. The service owns its accepted socket throughout; these server
helpers never close, detach or transfer it. The caller closes its own socket
once, including failure paths, and suppresses output on cleanup uncertainty.

Neither socket path, peer, request shape nor response shape proves issuance,
durable outcome, token delivery or current session state. The old token is
ephemeral request data and is neither logged nor journaled here. Request raw8
must not be persisted by composition. There is no reconnect, automatic retry,
fallback error send, signing, key custody, decryption, response admission,
cookie handling or public activation route in this transport.

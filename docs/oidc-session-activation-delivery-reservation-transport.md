# Private consume-reservation exchange

This fixed protocol is source only, not a deployed or demonstrated service.
It is distinct from activation reservation and consume-grant issuance.

The listener is
`/run/serverware/oidc-session-activation-delivery-execution/reserver.sock`.
The serving role is UID/GID 65499 and admits private peer 65532 before reading
any body. The client verifies kernel peer 0:0 for the root-created socket; that
is not measured service identity or a substitute for original signature checks.

Request magic `SWODRQ01` precedes five uint64 big-endian lengths and these raw
originals, in order: caller authorization, signed consume plan, encrypted consume
bundle, canonical closed expectations and consume grant. Response magic
`SWODRR01` precedes three lengths and the signed reserve, exact canonical
computation snapshot and signed state acknowledgment. No AES key or plaintext
token is transported.

Individual frame caps, ciphertext minimum and the total request bound are
checked before allocating bodies. Both headers and the largest allowed response
are reserved inside a single 64 MiB exchange cap; a larger permitted ciphertext
frame cannot enlarge it. The source profile fixes five request and three response
frames, eight-byte magics and that aggregate ceiling. Exact EOF is mandatory in
both directions, with a client half-close after the request.

The caller supplies an absolute monotonic deadline. A local 1–30-second timeout
can only shorten it. The same bound covers connect, peer admission, header/body
I/O, EOF and final return. The socket closes on success or failure; there is no
automatic retry or error packet claiming that publication did not occur.

The [cold serving owner](oidc-session-activation-delivery-execution-reserver-service.md)
connects actual original caller/grant replay,
root-held predecessor and local journal pins, the actual receiving custodian and
[durable delivery](oidc-session-activation-delivery-reservation-delivery.md), then
clips the original request window to the signed reserve expiry through response.
It spends every accepted connection, including rejection or uncertain
delivery. The codec itself does not provide that lifecycle or current authority.

Returned raw3 is unverified. A receiver must independently authenticate the
original reserve/snapshot/ACK and live caller/grant/private plan, then compare
separately held current-pending pins. Neither an ACK nor a successful socket
exchange supplies those expected pins or authorizes SQL. The actual cold SQL
pending consumer remains open; its independently pinned
[bootstrap](oidc-session-activation-delivery-execution-sql-bootstrap.md) alone
does not close that connection or token-release row 12.

# Consume-grant private transport

The [fixed transport](../serverware/authority_oidc_session_activation_delivery_execution_authorizer_transport.py)
uses a dedicated Unix socket at
`/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock`.
It neither widens the activation-authorizer protocol nor performs grant admission.

The `SWODGQ01` request has four immutable originals, each with a u64 big-endian
length after the eight-byte magic:

1. Original signed consume caller authorization, at most 64 KiB.
2. Original signed consume plan, at most 16 KiB.
3. Original encrypted consume bundle, within its distinct codec cap.
4. Closed canonical expectation data (`request`, `scope`, `journalDigest`),
   within the actual expectation module's 2 MiB cap.

The `SWODGR01` response contains one original signed consume grant, at most
64 KiB. No plaintext token, private key, proof-success object, arbitrary error
text or generic operation selector is transferred.

## Bounds and lifecycle

The entire request plus response, including both framing headers, stays within
64 MiB. The maximum response is reserved before accepting request lengths;
per-frame limits cannot enlarge the exchange. All lengths are checked before
body allocation. Ciphertext framing is checked without decryption. Subsequent
grant admission independently includes its detached receiving originals in its
own aggregate bound: fitting the transport alone does not imply admission.

The actual [cold service](oidc-session-activation-delivery-execution-authorizer-service.md)
authenticates peer UID/GID 65532 before reading the request. Its fixed serving
role is UID/GID 65500. The client checks the root-created listener's kernel peer
as `0:0` before any body exchange; that is not a measured service identity or a
substitute for the independently enrolled grant signature.

The client requires an inherited absolute monotonic deadline and a source-fixed
endpoint tuple. A local timeout of 1–30 seconds can only shorten that deadline.
It half-closes the request; both directions require exact EOF. Connection
failures, malformed responses and partial writes close the socket without an
automatic retry. Missing output is not evidence that no grant was signed.

Returned bytes remain unverified. The [independent private verifier](oidc-session-activation-delivery-execution-grant-verification.md)
requires real caller/root/receiving custody and original proof replay; transport
success alone authorizes neither reservation nor SQL. AES keys are not delivered
to a public or control-plane client to make verification convenient.

This is source-only protocol and uninstalled service packaging. No socket,
account, key or service is provisioned, and no build, runtime exchange or
production acceptance is demonstrated.

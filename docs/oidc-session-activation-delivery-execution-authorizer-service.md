# Consume execution authorizer service

[`oidc_session_activation_delivery_execution_authorizer_startup.py`](../serverware/oidc_session_activation_delivery_execution_authorizer_startup.py)
connects the dedicated cold consume-grant role to genuine
[role admission](oidc-session-activation-delivery-execution-authorizer-bootstrap.md),
[independent receiving custody](oidc-session-activation-delivery-execution-custody.md)
and [grant production](oidc-session-activation-delivery-execution-grant-production.md).
The operation is only `oidc.session.activation-delivery.consume`; neither the
activation grant role nor a generic registration grant is a fallback.

## Cold ownership and one accepted exchange

The startup API is `initialize_from_environment()`, `require_started()` and
`close()`. Only genuine initialization constructs its private singleton.
`require_started().serve_once()` returns false after a bounded idle wait or true
after its sole completed exchange. Every accepted connection spends the launch,
including a wrong peer, malformed request, cancellation or uncertain delivery.
No second accepted request or in-process restart is permitted.

The fixed process mode is
`oidc-session-activation-delivery-execution-authorizer`, UID/GID `65500`, with
empty supplementary groups and the exact eight-variable child environment.
The listener is
`/run/serverware/oidc-session-activation-delivery-execution/authorizer.sock`.
Requests require peer UID/GID `65532`; the client checks the root-created
listener's kernel peer as `0:0`, not as proof of measured service identity.

The eleven inherited descriptors are fixed:

| FD | Original or resource |
| --- | --- |
| 198 | Independent root public key |
| 199 | Signed authorizer role bootstrap |
| 200 | Root-created listener |
| 201 | Consume receiving-custody original |
| 202 | Consume planner bootstrap original |
| 203 | Planner-history custody original |
| 204 | Consume-grant receiving-history custody original |
| 205 | Consume execution-bundle AES key |
| 206 | Historical activation-bundle AES key |
| 207 | Delivery-custody AES key |
| 208 | Enrolled consume-grant signing key |

Genuine root/role admission precedes private-key loading. The actual receiving
owner is constructed from all four detached originals, the independently
role-bound receiver identity and three separately pinned raw32 AES keys. The
actual signer must match the dedicated enrolled authorizer public key. No key
or receiver configuration is learned from the request. The
[delivery profile](oidc-session-activation-delivery-execution-authorizer-delivery.md)
owns fixed paths, sealing and the permanent identity drop; it provisions nothing.

PID, UID/GID/groups, literal environment, sealed-original identities, listener
and path identities, exact descriptor inventory and the actual receiving
configuration remain guarded. Resource references are retained before later
callback checks can fail. Accepted sockets close on every exit; final request
liveness is checked after socket cleanup. `close()` drops held key references
and closes the receiving owner, duplicate listener and eleven adopted
descriptors. Host-local custody is not protection against a hostile root.

## Original windows and genuine grant production

One construction work allowance and real clock bracket open before sealed
original reads or root-key crypto. The role verifier and actual receiving
constructor get that same window and inherited deadline. Root-admitted policy
and expiry may only narrow it. The later role freshness sample is an additional
launch guard, never a replacement processing opening. Construction includes
charged original/key reads and final original-window checks after owner setup.

The original construction deadline and both clock brackets remain guards during
idle waits. The sole accepted request opens a separate work allowance/window
before peer or body intake; its deadline is intersected with the unchanged
startup bound. These are two explicit work phases, not renewed startup authority.

The [private transport](oidc-session-activation-delivery-execution-authorizer-transport.md)
carries raw4: signed caller authorization, signed consume plan, encrypted
consume-original bundle and canonical closed `{request, scope, journalDigest}`
expectations. Expectation capture uses the actual consume-only contract; received
deadline/age/skew can only narrow the original request window. Root, configuration,
enrollments, planner/operation keys and complete before-vector come from genuine
reauthentication of the original role and four detached custody documents.

The actual producer is invoked once with that receiving owner and the held
enrolled signer. Shared admission authenticates original caller/root controls,
and the receiver performs one full original-proof replay before signing; no
successful DTO, historical renewal or generic consume dispatch supplies authority.
The producer verifies its own exact signed output without a second full replay.
Startup reads that same-call grant's expiry only to clip transmission; it does
not invoke an additional full verifier. The unchanged request work/window and
sticky epoch/monotonic guards persist through send and final return.

`SWODGQ01` raw4 requests and `SWODGR01` raw1 grant responses reserve both headers
and the maximum 64 KiB response inside the whole 64 MiB exchange before body
allocation. Exact EOF is required. Only original signed token-free grant bytes
leave the service; the private journal, plaintext tokens and keys never do.
The client receives unverified bytes and must independently verify the grant.

A failed or partial exchange is not proof that no grant was signed. No success
is fabricated, no automatic retry is allowed, and no original expiry is renewed.
This service neither reserves pending state nor executes consume SQL, reconciles
completion, releases plaintext, establishes fresh public/user permission or
performs a portal handoff. Those are separate consumers and scopes.

Source-only implementation: no import execution, build, parser, test, runtime
verification, installation or provisioning was performed. An implemented cold
service is not an observed runtime grant or a production acceptance result.
